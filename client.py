#!/usr/bin/env python3
"""Monitor and manage ASIC devices through a remote server."""

import argparse
import asyncio
import curses
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Optional, Union
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COMMAND_TIMEOUT_PER_DEVICE = 120
load_dotenv(os.path.join(BASE_DIR, ".env"))


class APIError(Exception):
    pass


def api_request(
    server_url: str,
    token: str,
    path: str,
    method: str = "GET",
    body: Optional[dict] = None,
) -> Union[dict, bytes]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(
        f"{server_url.rstrip('/')}{path}",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    timeout = 10
    if method == "POST" and body is not None:
        devices = body.get("devices", [])
        if isinstance(devices, list):
            timeout += COMMAND_TIMEOUT_PER_DEVICE * min(len(devices), 20)
    try:
        with urlopen(request, timeout=timeout) as response:
            data = response.read()
            if "application/json" in response.headers.get("Content-Type", ""):
                result = json.loads(data)
                if not isinstance(result, dict):
                    raise ValueError("Сервер вернул неожиданный JSON")
                return result
            return data
    except HTTPError as exc:
        try:
            error_body = json.loads(exc.read())
            message = error_body.get("error", "request_failed")
        except (json.JSONDecodeError, AttributeError):
            message = "request_failed"
        raise APIError(f"HTTP {exc.code}: {message}") from exc


def get_telemetry(server_url: str, token: str) -> dict:
    result = api_request(server_url, token, "/api/devices")
    if not isinstance(result, dict) or not isinstance(
        result.get("devices"), list
    ):
        raise ValueError("Сервер вернул неожиданный формат телеметрии")
    return result


def add_devices_argument(command: argparse.ArgumentParser) -> None:
    command.add_argument("devices", nargs="+", help="IP-адреса ASIC")


def create_remote_monitor(server_url: str, token: str):
    from asic import DeviceMonitor, REBOOT_DURATION, REPORT_DIR

    class RemoteDeviceMonitor(DeviceMonitor):
        def __init__(self):
            super().__init__([], collect_faults=False)
            self.server_url = server_url
            self.server_token = token

        async def _init_async_resources(self):
            if self.lock is None:
                self.lock = asyncio.Lock()
            if not self.active_tasks:
                self.active_tasks.add(asyncio.create_task(
                    self._update_stats(), name="remote-telemetry-poller"
                ))

        async def _update_stats(self):
            while self.monitor_running:
                if self.monitor_paused:
                    await asyncio.sleep(1)
                    continue
                try:
                    result = await asyncio.to_thread(
                        get_telemetry, self.server_url, self.server_token
                    )
                    devices = [
                        device for device in result["devices"]
                        if isinstance(device, dict)
                        and isinstance(device.get("ip"), str)
                    ]
                    self.devices = [device["ip"] for device in devices]
                    async with self.lock:
                        self.stats_cache["all_devices"] = devices
                    for ip, (_, started_at, duration, _) in list(
                        self.operation_progress.items()
                    ):
                        if time.time() - started_at >= duration:
                            self.operation_progress.pop(ip, None)
                            self.restarting_devices.discard(ip)
                    updated_at = result.get("updated_at")
                    if updated_at:
                        self.last_stat_update = datetime.fromisoformat(
                            updated_at
                        ).timestamp()
                except Exception as exc:
                    logging.warning(
                        "Ошибка получения данных с сервера: %s", exc
                    )
                await asyncio.sleep(1)

        async def _send_action(self, action: str, **values):
            devices = sorted(self.selected_devices)
            if not devices:
                return None
            payload = {"devices": devices, **values}
            try:
                return await asyncio.to_thread(
                    api_request,
                    self.server_url,
                    self.server_token,
                    f"/api/commands/{action}",
                    "POST",
                    payload,
                )
            except Exception as exc:
                logging.error(
                    "Удалённая операция %s не выполнена: %s", action, exc
                )
                return None

        async def reboot_devices(self) -> int:
            result = await self._send_action("reboot")
            if not isinstance(result, dict):
                return 0
            for ip in result.get("queued_devices", []):
                self.restarting_devices.add(ip)
                self.operation_progress[ip] = (
                    "reboot", time.time(), REBOOT_DURATION, "final"
                )
            return result.get("queued", 0)

        async def set_led_mode(self) -> bool:
            result = await self._send_action("led")
            return bool(isinstance(result, dict) and result.get("success"))

        async def set_power_mode(self, mode: str) -> bool:
            result = await self._send_action("power-mode", mode=mode)
            return bool(isinstance(result, dict) and result.get("success"))

        async def set_power_limit(self, power: int) -> bool:
            result = await self._send_action("power-limit", power=power)
            return bool(isinstance(result, dict) and result.get("success"))

        async def set_pools(self, pools: list) -> bool:
            result = await self._send_action("pools", pools=pools)
            return bool(isinstance(result, dict) and result.get("success"))

        async def factory_reset(self) -> bool:
            result = await self._send_action(
                "factory-reset", confirm="FACTORY_RESET"
            )
            return bool(isinstance(result, dict) and result.get("success"))

        async def get_fault_chart_data(self, ip, period: str):
            query = {"period": period}
            if ip:
                query["device"] = ip
            result = await asyncio.to_thread(
                api_request,
                self.server_url,
                self.server_token,
                f"/api/faults?{urlencode(query)}",
            )
            if not isinstance(result, dict):
                return []
            return [
                (point["time"], point["count"])
                for point in result.get("points", [])
            ]

        async def export_fault_report(self, period: str, ip):
            query = {"period": period}
            if ip:
                query["device"] = ip
            report_data = await asyncio.to_thread(
                api_request,
                self.server_url,
                self.server_token,
                f"/api/faults/report?{urlencode(query)}",
            )
            if not isinstance(report_data, bytes):
                raise OSError("Сервер не вернул CSV-файл")
            os.makedirs(REPORT_DIR, exist_ok=True)
            scope = "all" if ip is None else ip.replace(".", "-")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            report_path = os.path.join(
                REPORT_DIR,
                f"fault_report_remote_{scope}_{period}_{timestamp}.csv",
            )
            with open(report_path, "wb") as report_file:
                report_file.write(report_data)
            return report_path

    return RemoteDeviceMonitor()


def run_console(server_url: str, token: str) -> None:
    monitor = create_remote_monitor(server_url, token)

    def curses_main(stdscr):
        try:
            asyncio.run(monitor.monitor(stdscr))
        except KeyboardInterrupt:
            logging.info("Удалённая консоль остановлена")

    curses.wrapper(curses_main)


def main() -> None:
    parser = argparse.ArgumentParser(description="ASIC telemetry client")
    parser.add_argument(
        "--server",
        required=True,
        help="URL сервера, например http://host:8080",
    )
    parser.add_argument("--interval", type=int, default=5)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("console", help="полная curses-консоль ASIC")
    watch = commands.add_parser(
        "watch", help="непрерывно показывать телеметрию"
    )
    watch.add_argument(
        "--interval", type=int, default=argparse.SUPPRESS
    )
    commands.add_parser("status", help="получить текущую телеметрию один раз")

    faults = commands.add_parser("faults", help="график ошибок по времени")
    faults.add_argument(
        "--period", choices=("day", "week", "month"), default="day"
    )
    faults.add_argument("--device", help="IP одного ASIC")

    report = commands.add_parser("fault-report", help="выгрузить ошибки в CSV")
    report.add_argument(
        "--period", choices=("day", "week", "month"), default="day"
    )
    report.add_argument("--device", help="IP одного ASIC")
    report.add_argument("--output", required=True, help="куда сохранить CSV")

    reboot = commands.add_parser("reboot", help="перезагрузить ASIC")
    add_devices_argument(reboot)

    mode = commands.add_parser("power-mode", help="изменить режим мощности")
    mode.add_argument(
        "--mode", choices=("normal", "low", "high"), required=True
    )
    add_devices_argument(mode)

    power = commands.add_parser("power-limit", help="задать лимит мощности")
    power.add_argument("--power", type=int, required=True)
    add_devices_argument(power)

    pools = commands.add_parser("pools", help="задать пулы из JSON-файла")
    pools.add_argument(
        "--file", required=True, help="JSON с одним-тремя пулами"
    )
    add_devices_argument(pools)

    led = commands.add_parser("led", help="включить зелёный LED")
    add_devices_argument(led)

    reset = commands.add_parser("factory-reset", help="сбросить ASIC")
    reset.add_argument(
        "--confirm",
        choices=("FACTORY_RESET",),
        required=True,
        help="явное подтверждение сброса",
    )
    add_devices_argument(reset)

    args = parser.parse_args()
    if args.interval < 1:
        parser.error("Интервал должен быть не меньше 1 секунды")

    token = os.getenv("ASIC_SERVER_TOKEN", "")
    if not token:
        parser.error("Задайте ASIC_SERVER_TOKEN в окружении или .env")

    if args.command in {None, "console"}:
        run_console(args.server, token)
        return

    if args.command == "watch":
        while True:
            try:
                data = get_telemetry(args.server, token)
                print(
                    json.dumps(data, ensure_ascii=False, indent=2),
                    flush=True,
                )
            except (
                APIError,
                URLError,
                TimeoutError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                print(
                    f"Ошибка получения телеметрии: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            time.sleep(args.interval)

    if args.command == "status":
        result = get_telemetry(args.server, token)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.command == "faults":
        query = {"period": args.period}
        if args.device:
            query["device"] = args.device
        result = api_request(
            args.server, token, f"/api/faults?{urlencode(query)}"
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.command == "fault-report":
        query = {"period": args.period}
        if args.device:
            query["device"] = args.device
        result = api_request(
            args.server, token, f"/api/faults/report?{urlencode(query)}"
        )
        if not isinstance(result, bytes):
            raise ValueError("Сервер не вернул CSV-файл")
        with open(args.output, "wb") as report_file:
            report_file.write(result)
        print(f"CSV сохранён: {args.output}")
        return

    action_paths = {
        "reboot": "/api/commands/reboot",
        "power-mode": "/api/commands/power-mode",
        "power-limit": "/api/commands/power-limit",
        "pools": "/api/commands/pools",
        "led": "/api/commands/led",
        "factory-reset": "/api/commands/factory-reset",
    }
    payload = {"devices": args.devices}
    if args.command == "power-mode":
        payload["mode"] = args.mode
    elif args.command == "power-limit":
        payload["power"] = args.power
    elif args.command == "pools":
        with open(args.file, "r", encoding="utf-8") as pools_file:
            payload["pools"] = json.load(pools_file)
    elif args.command == "factory-reset":
        payload["confirm"] = args.confirm

    result = api_request(
        args.server,
        token,
        action_paths[args.command],
        method="POST",
        body=payload,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (APIError, URLError, TimeoutError, OSError, ValueError) as exc:
        print(f"Ошибка клиента: {exc}", file=sys.stderr)
        sys.exit(1)
