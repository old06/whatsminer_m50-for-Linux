#!/usr/bin/env python3
"""Authenticated HTTP service for monitoring and managing ASIC devices."""

import argparse
import asyncio
import hmac
import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Type
from urllib.parse import parse_qs, urlsplit

from dotenv import load_dotenv

from asic import (
    DeviceMonitor,
    ValidationError,
    configure_logging,
    export_fault_report,
    fault_chart_data,
    scan_network,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
MAX_SERVER_SCAN_ADDRESSES = 4096
MAX_MANAGED_DEVICES_PER_REQUEST = 20
COMMAND_TIMEOUT_PER_DEVICE = 120
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def validate_scan_network(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Укажите корректную IPv4-сеть"
        ) from exc

    if not isinstance(network, ipaddress.IPv4Network) or not any(
        network.subnet_of(private_network)
        for private_network in RFC1918_NETWORKS
    ):
        raise argparse.ArgumentTypeError(
            "Серверное обнаружение разрешено только в приватной IPv4-сети"
        )
    if network.num_addresses > MAX_SERVER_SCAN_ADDRESSES:
        raise argparse.ArgumentTypeError(
            "Размер сети не должен превышать "
            f"{MAX_SERVER_SCAN_ADDRESSES} адресов"
        )
    return str(network)


def make_handler(
    monitor: DeviceMonitor,
    client_tokens: dict,
    loop: asyncio.AbstractEventLoop,
    operation_lock: asyncio.Lock,
) -> Type[BaseHTTPRequestHandler]:
    class TelemetryHandler(BaseHTTPRequestHandler):
        def _client_id(self):
            supplied_token = self.headers.get("Authorization", "")
            if not supplied_token.startswith("Bearer "):
                return None
            supplied_token = supplied_token[7:]
            for client_id, token in client_tokens.items():
                if hmac.compare_digest(
                    supplied_token.encode("utf-8"), token.encode("utf-8")
                ):
                    return client_id
            return None

        def _authorize(self) -> Optional[str]:
            client_id = self._client_id()
            if client_id is not None:
                logging.info("Авторизован API-клиент %s", client_id)
                return client_id
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "unauthorized"},
            )
            return None

        def do_GET(self) -> None:
            if self._authorize() is None:
                return

            parsed_path = urlsplit(self.path)
            if parsed_path.path == "/api/devices":
                updated_at = (
                    datetime.fromtimestamp(
                        monitor.last_stat_update, timezone.utc
                    ).isoformat()
                    if monitor.last_stat_update
                    else None
                )
                self._send_json(HTTPStatus.OK, {
                    "updated_at": updated_at,
                    "devices": list(
                        monitor.stats_cache.get("all_devices", [])
                    ),
                })
                return

            query = parse_qs(parsed_path.query)
            if parsed_path.path in {"/api/faults", "/api/faults/report"}:
                try:
                    period = query.get("period", ["day"])[0]
                    device_ip = query.get("device", [None])[0]
                    self._validate_fault_filter(period, device_ip)
                    if parsed_path.path == "/api/faults":
                        points = fault_chart_data(
                            monitor.fault_journal, device_ip, period
                        )
                        self._send_json(HTTPStatus.OK, {
                            "period": period,
                            "device": device_ip,
                            "points": [
                                {"time": label, "count": count}
                                for label, count in points
                            ],
                        })
                    else:
                        report_path = export_fault_report(
                            monitor.fault_journal, period, device_ip
                        )
                        with open(report_path, "rb") as report:
                            self._send_bytes(
                                HTTPStatus.OK,
                                report.read(),
                                "text/csv; charset=utf-8",
                                "attachment; filename="
                                f'"{os.path.basename(report_path)}"',
                            )
                except ValueError as exc:
                    self._send_json(
                        HTTPStatus.BAD_REQUEST, {"error": str(exc)}
                    )
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def _validate_fault_filter(
            self, period: str, device_ip: Optional[str]
        ) -> None:
            if period not in {"day", "week", "month"}:
                raise ValueError("period must be day, week, or month")
            if device_ip is not None:
                try:
                    normalized_ip = str(ipaddress.IPv4Address(device_ip))
                except ipaddress.AddressValueError as exc:
                    raise ValueError("invalid device IP") from exc
                if normalized_ip not in monitor.devices:
                    raise ValueError("unknown device IP")

        def do_POST(self) -> None:
            if self._authorize() is None:
                return
            route_to_action = {
                "/api/commands/reboot": "reboot",
                "/api/commands/power-mode": "power-mode",
                "/api/commands/power-limit": "power-limit",
                "/api/commands/pools": "pools",
                "/api/commands/led": "led",
                "/api/commands/factory-reset": "factory-reset",
            }
            action = route_to_action.get(urlsplit(self.path).path)
            if action is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return

            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= content_length <= 65536:
                    raise ValueError("request body must be 1..65536 bytes")
                payload = json.loads(self.rfile.read(content_length))
                if not isinstance(payload, dict):
                    raise ValueError("request body must be a JSON object")
                requested_devices = payload.get("devices", [])
                device_count = (
                    min(
                        len(requested_devices),
                        MAX_MANAGED_DEVICES_PER_REQUEST,
                    )
                    if isinstance(requested_devices, list)
                    else 1
                )
                result = asyncio.run_coroutine_threadsafe(
                    execute_command(
                        monitor, operation_lock, action, payload
                    ),
                    loop,
                ).result(
                    timeout=(COMMAND_TIMEOUT_PER_DEVICE * device_count) + 10
                )
            except (ValueError, ValidationError, json.JSONDecodeError) as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": str(exc)}
                )
                return
            except TimeoutError:
                self._send_json(
                    HTTPStatus.GATEWAY_TIMEOUT,
                    {"error": "operation_timeout"},
                )
                return
            except Exception:
                logging.exception("Ошибка выполнения команды API %s", action)
                self._send_json(
                    HTTPStatus.BAD_GATEWAY,
                    {"error": "device_operation_failed"},
                )
                return

            self._send_json(HTTPStatus.OK, result)

        def _send_json(self, status: HTTPStatus, body: dict) -> None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self._send_bytes(
                status,
                payload,
                "application/json; charset=utf-8",
            )

        def _send_bytes(
            self,
            status: HTTPStatus,
            payload: bytes,
            content_type: str,
            content_disposition: Optional[str] = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            if content_disposition:
                self.send_header(
                    "Content-Disposition", content_disposition
                )
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format_string: str, *args: object) -> None:
            logging.info("Telemetry API: %s", format_string % args)

    return TelemetryHandler


async def execute_command(
    monitor: DeviceMonitor,
    operation_lock: asyncio.Lock,
    action: str,
    payload: dict,
) -> dict:
    raw_devices = payload.get("devices")
    if (
        not isinstance(raw_devices, list)
        or not raw_devices
        or len(raw_devices) > MAX_MANAGED_DEVICES_PER_REQUEST
        or any(not isinstance(value, str) for value in raw_devices)
    ):
        raise ValueError(
            "devices must contain 1..20 IPv4 addresses"
        )

    try:
        devices = {str(ipaddress.IPv4Address(value)) for value in raw_devices}
    except ipaddress.AddressValueError as exc:
        raise ValueError("devices must contain valid IPv4 addresses") from exc
    if len(devices) != len(raw_devices):
        raise ValueError("devices must not contain duplicates")
    unknown_devices = devices - set(monitor.devices)
    if unknown_devices:
        raise ValueError(
            "unknown devices: " + ", ".join(sorted(unknown_devices))
        )

    async with operation_lock:
        monitor.selected_devices = devices
        if action == "reboot":
            queued_devices = sorted(
                devices - monitor.pending_operation_devices
            )
            queued = await monitor.reboot_devices()
            return {
                "success": queued == len(devices),
                "queued": queued,
                "queued_devices": queued_devices,
            }
        if action == "power-mode":
            mode = payload.get("mode")
            if not isinstance(mode, str) or mode not in {
                "normal", "low", "high"
            }:
                raise ValueError("mode must be normal, low, or high")
            succeeded = await monitor.set_power_mode(mode)
        elif action == "power-limit":
            power = payload.get("power")
            if isinstance(power, bool) or not isinstance(power, int):
                raise ValueError("power must be an integer")
            succeeded = await monitor.set_power_limit(power)
        elif action == "pools":
            succeeded = await monitor.set_pools(payload.get("pools"))
        elif action == "led":
            succeeded = await monitor.set_led_mode()
        elif action == "factory-reset":
            if payload.get("confirm") != "FACTORY_RESET":
                raise ValueError(
                    "factory reset requires confirm=FACTORY_RESET"
                )
            succeeded = await monitor.factory_reset()
        else:
            raise ValueError("unsupported operation")

    return {"success": succeeded, "devices": sorted(devices)}


async def refresh_devices(
    monitor: DeviceMonitor, network: str, interval: int
) -> None:
    while True:
        try:
            devices = await scan_network(network)
            monitor.devices = devices
            logging.info("Обнаружено устройств: %d", len(devices))
        except Exception:
            logging.exception("Ошибка поиска ASIC в сети %s", network)
        await asyncio.sleep(interval)


async def run_server(
    network: str,
    host: str,
    port: int,
    scan_interval: int,
    client_tokens: dict,
) -> None:
    monitor = DeviceMonitor([])
    await monitor._init_async_resources()
    loop = asyncio.get_running_loop()
    operation_lock = asyncio.Lock()
    http_server = ThreadingHTTPServer(
        (host, port),
        make_handler(monitor, client_tokens, loop, operation_lock),
    )
    http_server.daemon_threads = True
    scan_task = asyncio.create_task(
        refresh_devices(monitor, network, scan_interval),
        name="device-discovery",
    )
    serve_task = asyncio.create_task(
        asyncio.to_thread(http_server.serve_forever),
        name="telemetry-http-server",
    )

    logging.info("API телеметрии запущен на http://%s:%d", host, port)
    try:
        await serve_task
    finally:
        scan_task.cancel()
        await asyncio.gather(scan_task, return_exceptions=True)
        http_server.shutdown()
        http_server.server_close()
        await asyncio.gather(serve_task, return_exceptions=True)
        await monitor.cleanup()


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser(description="ASIC telemetry server")
    parser.add_argument("--network", required=True, type=validate_scan_network)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--scan-interval", type=int, default=300)
    args = parser.parse_args()

    raw_client_tokens = os.getenv("ASIC_CLIENT_TOKENS", "")
    if raw_client_tokens:
        try:
            client_tokens = json.loads(raw_client_tokens)
        except json.JSONDecodeError:
            parser.error("ASIC_CLIENT_TOKENS должен быть JSON-объектом")
        if (
            not isinstance(client_tokens, dict)
            or not client_tokens
            or any(
                not isinstance(client_id, str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", client_id)
                or not isinstance(token, str)
                or len(token) < 32
                for client_id, token in client_tokens.items()
            )
            or len(set(client_tokens.values())) != len(client_tokens)
        ):
            parser.error(
                "ASIC_CLIENT_TOKENS должен содержать уникальные токены "
                "длиной от 32 символов для каждого клиента"
            )
    else:
        legacy_token = os.getenv("ASIC_SERVER_TOKEN", "")
        if len(legacy_token) < 32:
            parser.error(
                "Задайте ASIC_CLIENT_TOKENS или ASIC_SERVER_TOKEN "
                "(минимум 32 символа)"
            )
        client_tokens = {"admin": legacy_token}

    if not 1 <= args.port <= 65535:
        parser.error("Порт должен быть в диапазоне 1..65535")
    if args.scan_interval < 30:
        parser.error("Интервал поиска должен быть не меньше 30 секунд")

    try:
        asyncio.run(run_server(
            args.network,
            args.host,
            args.port,
            args.scan_interval,
            client_tokens,
        ))
    except KeyboardInterrupt:
        logging.info("Сервер остановлен")


if __name__ == "__main__":
    main()
