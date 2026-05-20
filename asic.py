#!/usr/bin/env python3
import curses
import nmap
import json
import hashlib
import base64
import time
import os
import logging
import asyncio
from logging.handlers import TimedRotatingFileHandler
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from dotenv import load_dotenv
import argparse
from typing import Dict, List, Set, Tuple, Optional, Any
import binascii

load_dotenv()

CONFIG_FILE = "asic_devices.json"
API_PORT = 4433
ACCOUNTS = {
    "super": os.getenv("SUPER_PASSWORD", ""),
    "user1": os.getenv("USER1_PASSWORD", ""),
    "user2": os.getenv("USER2_PASSWORD", ""),
    "user3": os.getenv("USER3_PASSWORD", "")
}
MONITOR_INTERVAL = 0.05
STATS_UPDATE_INTERVAL = 1
REBOOT_DURATION = 60
UPDATE_DURATION = 300
MAX_CONCURRENT_OPS = 10
COMMAND_RETRIES = 3
CONNECTION_TIMEOUT = 15
READ_TIMEOUT = 50
CHUNK_SIZE = 4096
DEFAULT_FIRMWARE = "firmware.bin"
ENCRYPTED_COMMANDS = {'set.miner.pools', 'set.user.change_passwd', 'set.miner.power_percent'}
OVERHEAT_TEMP = 80  # Температура перегрева

log_handler = TimedRotatingFileHandler(
    'asic_monitor.log',
    when='midnight',
    interval=1,
    backupCount=7
)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[log_handler]
)

class DeviceError(Exception):
    """Базовое исключение для ошибок устройства"""
    pass

class ConnectionError(DeviceError):
    """Ошибка подключения к устройству"""
    pass

class CommandError(DeviceError):
    """Ошибка выполнения команды"""
    pass

class ValidationError(DeviceError):
    """Ошибка валидации"""
    pass

class DeviceMonitor:
    def __init__(self, devices: List[str]):
        self.devices = devices
        self.monitor_running = True
        self.current_account = "super"
        self.last_stat_update = 0
        self.current_row = 0
        self.scroll_offset = 0
        self.monitor_paused = False
        self.selected_devices: Set[str] = set()
        self.active_tasks: Set[asyncio.Task] = set()
        self.device_states: Dict[str, Dict] = defaultdict(dict)
        self.device_errors: Dict[str, List] = defaultdict(list)
        self.salt_cache: Dict[str, str] = {}
        self.stats_cache = {"all_devices": []}
        self.operation_queue = None
        self.operation_progress: Dict[str, Tuple] = {}
        self.firmware_path = DEFAULT_FIRMWARE
        self.lock = None
        self.restarting_devices: Set[str] = set()
        self.detailed_view = False  # Режим детального просмотра устройства
        
        self.ERROR_CODES = {
            0: "Успех",
            -1: "Общая ошибка",
            -2: "Неверная команда",
            -3: "Неверный JSON",
            -4: "Нет прав",
            -5: "Недостаточно памяти",
            -6: "Ошибка прошивки",
            -7: "Неверная сигнатура",
            -8: "Недостаточно места",
            -9: "Ошибка проверки",
            -999: "Сетевая ошибка"
        }

    async def _init_async_resources(self):
        if self.operation_queue is None:
            self.operation_queue = asyncio.Queue()
        if self.lock is None:
            self.lock = asyncio.Lock()
        if not self.active_tasks:
            self.active_tasks.update({
                asyncio.create_task(self._process_operations()),
                asyncio.create_task(self._update_progress_bars()),
                asyncio.create_task(self._update_stats())
            })

    async def monitor(self, stdscr):
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.nodelay(True)
        curses.cbreak()
        self._init_colors()
        await self._init_async_resources()

        try:
            while self.monitor_running:
                await self._handle_input(stdscr)
                await self._draw_interface(stdscr)
                await asyncio.sleep(MONITOR_INTERVAL)
        finally:
            curses.endwin()
            await self.cleanup()

    def _init_colors(self):
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_RED, -1)          # Ошибка/оффлайн
            curses.init_pair(2, curses.COLOR_YELLOW, -1)       # Предупреждение
            curses.init_pair(3, curses.COLOR_BLUE, -1)         # Информация
            curses.init_pair(4, curses.COLOR_GREEN, -1)        # Онлайн
            curses.init_pair(5, curses.COLOR_CYAN, -1)        # Прогресс
            curses.init_pair(6, curses.COLOR_MAGENTA, -1)      # Выделение
            curses.init_pair(7, curses.COLOR_WHITE, -1)        # Обычный текст
            curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_YELLOW)  # Перезагрузка
            curses.init_pair(9, curses.COLOR_RED, curses.COLOR_YELLOW)    # Перегрев

    async def _handle_input(self, stdscr):
        KEY_UP = curses.KEY_UP if hasattr(curses, 'KEY_UP') else 259
        KEY_DOWN = curses.KEY_DOWN if hasattr(curses, 'KEY_DOWN') else 258

        key = stdscr.getch()
        while key != -1:
            if key in [ord('q'), 27]:
                self.monitor_running = False
            elif key in [KEY_UP, 259, 65]:
                self._handle_key_up()
            elif key in [KEY_DOWN, 258, 66]:
                self._handle_key_down()
            elif key == ord(' '):
                self._toggle_device_selection()
            elif key == ord('a'):
                self._toggle_all_devices()
            elif key == ord('r'):
                await self.reboot_devices()
            elif key == ord('u'):
                await self.update_firmware()
            elif key == ord('p'):
                self.monitor_paused = not self.monitor_paused
            elif key == ord('f'):
                await self._show_fan_menu(stdscr)
            elif key == ord('l'):
                await self.set_led_mode()
            elif key == ord('m'):
                await self._show_power_menu(stdscr)
            elif key == ord('L'):
                await self._set_power_limit_dialog(stdscr)
            elif key == ord('P'):
                await self._set_pools_dialog(stdscr)
            elif key == ord('d'):
                self.detailed_view = not self.detailed_view  # Переключение детального просмотра
            elif key == ord('F'):
                await self.factory_reset()
            elif key == ord('C'):
                await self._set_frequency_dialog(stdscr)
            elif key == ord('V'):
                await self._set_voltage_dialog(stdscr)
            elif key == ord('G'):
                await self._get_logs_dialog(stdscr)
            elif key == ord('H'):
                await self._show_hashboard_info()
            elif key == ord('B'):
                await self._backup_config_dialog(stdscr)
            elif key == ord('N'):
                await self._change_password_dialog(stdscr)
            key = stdscr.getch()

    def _handle_key_up(self):
        if self.current_row > 0:
            self.current_row -= 1
            if self.current_row < self.scroll_offset:
                self.scroll_offset = self.current_row

    def _handle_key_down(self):
        valid_data = self._get_sorted_devices()
        total_items = len(valid_data)
        h, _ = curses.getsyx()
        max_visible_rows = h - 8
        
        if self.current_row < total_items - 1:
            self.current_row += 1
            if self.current_row >= self.scroll_offset + max_visible_rows:
                self.scroll_offset += 1

    def _toggle_device_selection(self):
        valid_data = self._get_sorted_devices()
        if self.current_row < len(valid_data):
            selected_ip = valid_data[self.current_row]["ip"]
            if selected_ip in self.selected_devices:
                self.selected_devices.remove(selected_ip)
            else:
                self.selected_devices.add(selected_ip)

    def _toggle_all_devices(self):
        valid_data = self._get_sorted_devices()
        if len(self.selected_devices) != len(valid_data):
            self.selected_devices = {d['ip'] for d in valid_data}
        else:
            self.selected_devices.clear()

    async def _draw_interface(self, stdscr):
        h, w = stdscr.getmaxyx()
        valid_data = self._get_sorted_devices()
        
        if self.detailed_view and valid_data and self.current_row < len(valid_data):
            await self._draw_device_details(stdscr, valid_data[self.current_row], h, w)
            return
            
        online_devices = [d for d in valid_data if d.get('online') and d['ip'] not in self.restarting_devices]
        total_hashrate = sum(d.get('hashrate', 0) for d in online_devices)
        total_power = sum(d.get('power', 0) for d in online_devices)
        avg_temp = sum(d.get('temp', 0) for d in online_devices) / len(online_devices) if online_devices else 0
        online_count = len(online_devices)
        offline_count = len(valid_data) - online_count - len(self.restarting_devices)

        stdscr.erase()
        
        header = f"ASIC Monitor v1.2 | Устройств: {len(valid_data)} (ON: {online_count} OFF: {offline_count} RST: {len(self.restarting_devices)})"
        stats = f"Хэшрейт: {total_hashrate:.1f} TH/s | Питание: {total_power/1000:.1f} kW | Темп: {avg_temp:.1f}°C"
        self._safe_addstr(stdscr, 0, 0, header, curses.A_BOLD | curses.color_pair(7))
        self._safe_addstr(stdscr, 1, 0, stats, curses.color_pair(7))
        
        self._draw_devices_list(stdscr, h, w, valid_data)
        self._draw_progress_bars(stdscr, h, w)
        
        help_text = (
            "[Space]Выбор [A]Все [R]Рестарт [U]Обновить [F]Вент [L]LED [M]Питание [L]Лимит [P]Пулы [D]Детали "
            "[C]Частота [V]Напряжение [G]Логи [H]Хеш [B]Бэкап [N]Пароль [F]Сброс [Q]Выход"
        )
        self._safe_addstr(stdscr, h-1, 0, help_text.ljust(w-1), curses.A_REVERSE)
        stdscr.refresh()

    async def _draw_device_details(self, stdscr, device: Dict, h: int, w: int):
        stdscr.erase()
        
        # Основная информация
        title = f"Детальная информация: {device['ip']}"
        stdscr.addstr(0, 0, title, curses.A_BOLD | curses.color_pair(7))
        
        # Разделительная линия
        stdscr.addstr(1, 0, "-" * (w-1), curses.color_pair(7))
        
        # Основные параметры
        rows = [
            f"Статус: {'ONLINE' if device.get('online') else 'OFFLINE'}",
            f"Модель: {device.get('model', 'N/A')}",
            f"Прошивка: {device.get('fw_version', 'N/A')}",
            f"Серийный номер: {device.get('sn', 'N/A')}",
            f"Время работы: {device.get('uptime', 'N/A')}",
            f"Температура: {device.get('temp', 0):.1f}°C",
            f"Хэшрейт: {device.get('hashrate', 0):.1f} TH/s",
            f"Питание: {device.get('power', 0)/1000:.1f} kW",
            f"Вентиляторы: {device.get('fan_in', 0)}/{device.get('fan_out', 0)} RPM",
            f"Частота: {device.get('target_freq', 0)}%"
        ]
        
        for i, row in enumerate(rows):
            stdscr.addstr(3 + i, 0, row, curses.color_pair(7))
        
        # Разделительная линия
        stdscr.addstr(13, 0, "-" * (w-1), curses.color_pair(7))
        
        # Информация о пулах
        stdscr.addstr(14, 0, "Пулы майнинга:", curses.A_BOLD | curses.color_pair(7))
        for i, pool in enumerate(device.get('pools', [])[:3]):
            status_color = curses.color_pair(4) if pool.get('status') == 'alive' else curses.color_pair(1)
            pool_text = f"{i+1}. {pool.get('url', 'N/A')}"
            stdscr.addstr(15 + i*2, 2, pool_text, status_color)
            worker_text = f"Worker: {pool.get('worker', 'N/A')} | Status: {pool.get('status', 'N/A')}"
            stdscr.addstr(16 + i*2, 4, worker_text, curses.color_pair(3))
        
        # Кнопка возврата
        help_text = "[D]Назад [Q]Выход"
        stdscr.addstr(h-1, 0, help_text.ljust(w-1), curses.A_REVERSE)
        stdscr.refresh()

    def _get_sorted_devices(self):
        return sorted(
            [d for d in self.stats_cache["all_devices"] if isinstance(d, dict)],
            key=lambda x: (not x.get('online'), x.get('hashrate', 0)),
            reverse=True
        )

    def _safe_addstr(self, stdscr, y, x, text, attr=0):
        try:
            max_width = stdscr.getmaxyx()[1] - x
            if max_width <= 0:
                return
            stdscr.addstr(y, x, text[:max_width], attr)
        except curses.error:
            pass

    def _draw_devices_list(self, stdscr, h, w, devices):
        max_visible_rows = h - 8
        start_row = 3
        
        for i in range(max_visible_rows):
            idx = i + self.scroll_offset
            if idx >= len(devices):
                break
            
            device = devices[idx]
            y = start_row + i
            color = self._get_device_color(device)
            status = self._get_device_status(device)
            
            if device['ip'] in self.selected_devices:
                color |= curses.A_REVERSE
            if idx == self.current_row:
                color |= curses.A_BOLD | curses.color_pair(6)
            
            line = self._format_device_line(device, status, w)
            stdscr.addstr(y, 0, line, color)

    def _format_device_line(self, device, status, width):
        fan_info = f"Fan: {device.get('fan_in', 0)}/{device.get('fan_out', 0)} RPM" if device.get('online') else ""
        freq_info = f"Freq: {device.get('target_freq', 0)}%" if device.get('online') else ""
        line = (f"{status} {device['ip']:15} | Temp: {device.get('temp', 0):.1f}°C | "
                f"Hash: {device.get('hashrate', 0):.1f} TH/s | Power: {device.get('power', 0)/1000:.1f} kW | "
                f"Up: {device.get('uptime', 'N/A')} | Ver: {device.get('fw_version', 'N/A')[:8]} | "
                f"{freq_info} {fan_info}")
        return line[:max(0, width-1)].ljust(width-1)

    def _get_device_color(self, device):
        if device['ip'] in self.restarting_devices:
            return curses.color_pair(8)
        if not device.get('online'):
            return curses.color_pair(1)
        if device.get('temp', 0) > OVERHEAT_TEMP:
            return curses.color_pair(9)
        return curses.color_pair(4)

    def _get_device_status(self, device):
        if device['ip'] in self.restarting_devices:
            return "[RST]"
        if device.get('temp', 0) > OVERHEAT_TEMP:
            return "[HOT]"
        return "[ON]" if device.get('online') else "[OFF]"

    def _draw_progress_bars(self, stdscr, h, w):
        progress_y = h - 4
        for ip, (op_type, start, duration, stage) in self.operation_progress.items():
            elapsed = time.time() - start
            progress = min(elapsed / duration, 1.0) if duration > 0 else 0
            bar_width = int(w * 0.6)
            filled = int(bar_width * progress)
            bar = '█' * filled + '-' * (bar_width - filled)
            stdscr.addstr(progress_y, 0, f"{ip}: {op_type} [{bar}] {progress:.0%}", curses.color_pair(5))
            progress_y += 1
            if progress_y >= h - 2:
                break

    async def _process_operations(self):
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_OPS)
        while self.monitor_running:
            async with semaphore:
                ip, operation = await self.operation_queue.get()
                try:
                    if operation == "reboot":
                        await self._reboot_device(ip)
                    elif operation == "update":
                        await self._update_device(ip)
                finally:
                    self.operation_queue.task_done()

    async def _update_progress_bars(self):
        while self.monitor_running:
            now = time.time()
            async with self.lock:
                for ip in list(self.operation_progress.keys()):
                    op_type, start, duration, stage = self.operation_progress[ip]
                    progress = min((now - start) / duration, 1.0) if duration > 0 else 0
                    if progress >= 1.0 and stage == "final":
                        self.operation_progress.pop(ip, None)
            await asyncio.sleep(0.1)

    async def _update_stats(self):
        while self.monitor_running:
            if self.monitor_paused:
                await asyncio.sleep(STATS_UPDATE_INTERVAL)
                continue

            try:
                tasks = [self.get_device_data(ip) for ip in self.devices]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                async with self.lock:
                    self.stats_cache["all_devices"] = [
                        r for r in results if not isinstance(r, Exception)
                    ]
                self.last_stat_update = time.time()
            except Exception as e:
                logging.error(f"Ошибка обновления статистики: {str(e)}")
            finally:
                await asyncio.sleep(STATS_UPDATE_INTERVAL)

    async def get_device_data(self, ip: str) -> Dict:
        if ip in self.restarting_devices:
            return {
                "ip": ip,
                "online": False,
                "fw_version": "N/A",
                "hashrate": 0,
                "temp": 0,
                "fan_in": 0,
                "fan_out": 0,
                "power": 0,
                "target_freq": 0,
                "uptime": "RESTARTING"
            }
        
        try:
            static_data = await self.send_command(ip, {"cmd": "get.device.info"})
            if static_data.get('code') != 0:
                return {"ip": ip, "online": False}
            
            status_data = await self.send_command(ip, {"cmd": "get.miner.status", "param": "summary"})
            setting_data = await self.send_command(ip, {"cmd": "get.miner.setting"})
            pools_data = await self.send_command(ip, {"cmd": "get.miner.status", "param": "pools"})
            pools = []
            if pools_data.get('code') == 0:
                raw_pools = pools_data.get('msg', {}).get('pools', [])
                for p in raw_pools:
                    pools.append({
                        "url": p.get('url', 'N/A'),
                        "worker": p.get('worker', 'N/A'),
                        "status": p.get('status', 'N/A'),
                        "passwd": '***' if p.get('passwd') else 'N/A'
                    })
    
            if status_data.get('code') != 0 or setting_data.get('code') != 0:
                return {"ip": ip, "online": False}

            summary = status_data.get('msg', {}).get('summary', {})
            static_msg = static_data.get('msg', {})
            
            return {
                "ip": ip,
                "online": True,
                "model": static_msg.get('miner', {}).get('type', 'N/A'),
                "sn": static_msg.get('miner', {}).get('miner-sn', 'N/A'),
                "fw_version": static_msg.get('system', {}).get('fwversion', 'N/A'),
                "hashrate": summary.get('hash-realtime', 0),
                "temp": summary.get('chip-temp-avg', 0),
                "fan_in": summary.get('fan-speed-in', 0),
                "fan_out": summary.get('fan-speed-out', 0),
                "power": summary.get('power-realtime', 0),
                "target_freq": summary.get('target-freq', 100),
                "uptime": self.format_uptime(summary.get('elapsed', 0)),
                "pools": pools
            }
        except Exception as e:
            logging.error(f"{ip}: Ошибка получения данных: {str(e)}")
            return {"ip": ip, "online": False}

    async def reboot_devices(self):
        if not self.selected_devices:
            return

        logging.info(f"Инициирована перезагрузка {len(self.selected_devices)} устройств")
        for ip in self.selected_devices:
            await self.operation_queue.put((ip, "reboot"))

    async def _reboot_device(self, ip: str):
        try:
            salt = await self.get_salt(ip)
            ts = int(time.time())
            resp = await self.send_command(ip, {
                "cmd": "set.system.reboot",
                "ts": ts,
                "token": self.generate_token("set.system.reboot", salt, ts),
                "account": self.current_account
            })
            if resp.get('code') == 0:
                self.operation_progress[ip] = ("reboot", time.time(), REBOOT_DURATION, "final")
                logging.info(f"{ip}: Успешная перезагрузка")
            else:
                logging.error(f"{ip}: Ошибка перезагрузки")
        except Exception as e:
            logging.exception(f"{ip}: Ошибка перезагрузки")
        finally:
            await self.force_refresh_device(ip, delay=REBOOT_DURATION + 5)

    async def update_firmware(self):
        if not self.selected_devices:
            return

        if not os.path.exists(self.firmware_path):
            logging.error(f"Файл прошивки {self.firmware_path} не найден!")
            return

        logging.info(f"Инициировано обновление {len(self.selected_devices)} устройств")
        for ip in self.selected_devices:
            await self.operation_queue.put((ip, "update"))
    async def _update_device(self, ip: str):
        writer = None
        try:
            salt = await self.get_salt(ip)
            ts = int(time.time())
            init_resp = await self.send_command(ip, {
                "cmd": "set.system.update_firmware",
                "ts": ts,
                "token": self.generate_token("set.system.update_firmware", salt, ts),
                "account": self.current_account
            })
        
            if init_resp.get('msg') != "ready":
                raise ConnectionError("Устройство не готово к обновлению")

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, API_PORT),
                timeout=CONNECTION_TIMEOUT
            )
            
            # Вычисление CRC32 файла
            with open(self.firmware_path, 'rb') as f:
                firmware_data = f.read()
            firmware_size = len(firmware_data)
            crc32 = binascii.crc32(firmware_data)
            
            # Отправка CRC32
            writer.write(crc32.to_bytes(4, 'little'))
            await writer.drain()
    
            # Проверка подтверждения CRC
            try:
                crc_confirmation = await asyncio.wait_for(reader.read(1), timeout=10)
            except asyncio.TimeoutError:
                raise ConnectionError("Таймаут подтверждения CRC")

            if crc_confirmation != b'\x01':
                raise ConnectionError(f"Ошибка CRC подтверждения: {crc_confirmation!r}")

            confirmation_received = False
            for attempt in range(3):
                try:
                    writer.write(firmware_size.to_bytes(4, 'little'))
                    await writer.drain()
                
                    confirmation = await asyncio.wait_for(reader.read(1), timeout=15)
                    logging.debug(f"Попытка {attempt+1}: Ответ устройства на размер: {confirmation}")

                    if confirmation == b'\x01':
                        confirmation_received = True
                        break
                    logging.warning(f"Попытка {attempt+1}: Неверный ответ подтверждения: {confirmation}")
                except asyncio.TimeoutError:
                    logging.warning(f"Попытка {attempt+1}: Таймаут подтверждения размера")

            if not confirmation_received:
                raise ConnectionError("Ошибка подтверждения размера прошивки")

            # Отправка данных прошивки
            sent = 0
            while sent < firmware_size:
                chunk_size = min(CHUNK_SIZE, firmware_size - sent)
                writer.write(firmware_data[sent:sent + chunk_size])
                await writer.drain()
                sent += chunk_size
                progress = sent / firmware_size
                self.operation_progress[ip] = ("update", time.time(), UPDATE_DURATION, f"upload {progress:.1%}")

            # Получение финального подтверждения
            try:
                final_confirmation = await asyncio.wait_for(reader.read(1), timeout=30)
            except asyncio.TimeoutError:
                raise ConnectionError("Таймаут финального подтверждения загрузки")

            if final_confirmation != b'\x01':
                raise ConnectionError(f"Ошибка подтверждения загрузки: {final_confirmation!r}")

            logging.info(f"{ip}: Прошивка успешно передана")
            self.operation_progress[ip] = ("update", time.time(), UPDATE_DURATION, "finalizing")
            await asyncio.sleep(UPDATE_DURATION)
        
        except Exception as e:
            logging.error(f"{ip}: Ошибка обновления: {str(e)}", exc_info=True)
            self.operation_progress.pop(ip, None)
        finally:
            if writer and not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            await self.force_refresh_device(ip, delay=30)

    async def force_refresh_device(self, ip: str, delay: int = 5):
        await asyncio.sleep(delay)
        try:
            data = await self.get_device_data(ip)
            async with self.lock:
                for i, dev in enumerate(self.stats_cache["all_devices"]):
                    if dev.get('ip') == ip:
                        self.stats_cache["all_devices"][i] = data
                        break
        except Exception as e:
            logging.error(f"{ip}: Ошибка обновления данных: {str(e)}")

    async def _show_fan_menu(self, stdscr):
        menu_items = [
            ("1", "Нормальный режим", "normal"),
            ("2", "Режим нулевой скорости", "zero"),
            ("q", "Назад", None)
        ]
        
        h, w = stdscr.getmaxyx()
        self._draw_menu(stdscr, "УПРАВЛЕНИЕ ВЕНТИЛЯТОРАМИ:", menu_items, h//2-3, w//2-15)
        
        while True:
            key = stdscr.getch()
            if key == ord('1'):
                await self.set_fan_mode("normal")
                break
            elif key == ord('2'):
                await self.set_fan_mode("zero")
                break
            elif key in [ord('q'), 27]:
                break

    async def set_fan_mode(self, mode: str):
        if not self.selected_devices:
            return

        for ip in self.selected_devices:
            salt = await self.get_salt(ip)
            ts = int(time.time())
            response = await self.send_command(ip, {
                "cmd": "set.fan.zero_speed",
                "ts": ts,
                "token": self.generate_token("set.fan.zero_speed", salt, ts),
                "account": self.current_account,
                "param": 1 if mode == "zero" else 0
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Режим вентиляторов изменен на {mode}")
            else:
                logging.error(f"{ip}: Ошибка изменения режима вентиляторов")

    async def set_led_mode(self):
        if not self.selected_devices:
            return

        for ip in self.selected_devices:
            salt = await self.get_salt(ip)
            ts = int(time.time())
            response = await self.send_command(ip, {
                "cmd": "set.system.led",
                "ts": ts,
                "token": self.generate_token("set.system.led", salt, ts),
                "account": self.current_account,
                "param": {
                    "color": "green",
                    "period": 1000,
                    "duration": 500,
                    "start": 0
                }
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Настройки LED изменены")
            else:
                logging.error(f"{ip}: Ошибка изменения LED")

    async def send_command(self, ip: str, command: Dict, retries: int = COMMAND_RETRIES) -> Dict:
        for attempt in range(retries):
            writer = None
            try:
                payload = dict(command)
                if payload['cmd'].startswith('set.'):
                    salt = await self.get_salt(ip)
                    ts = int(time.time())
                    payload.update({
                        "ts": ts,
                        "token": self.generate_token(payload['cmd'], salt, ts),
                        "account": self.current_account
                    })
                    if any(cmd in payload['cmd'] for cmd in ENCRYPTED_COMMANDS):
                        payload['param'] = self.encrypt_param(payload['param'], payload['cmd'], salt, ts)

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, API_PORT),
                    timeout=CONNECTION_TIMEOUT
                )
                
                data = json.dumps(payload, ensure_ascii=False).encode()
                writer.write(len(data).to_bytes(4, 'little'))
                await writer.drain()
                writer.write(data)
                await writer.drain()

                length_bytes = await asyncio.wait_for(reader.readexactly(4), READ_TIMEOUT)
                length = int.from_bytes(length_bytes, 'little')
                response_data = await asyncio.wait_for(reader.readexactly(length), READ_TIMEOUT)
                return json.loads(response_data.decode())
                
            except (asyncio.TimeoutError, ConnectionError) as e:
                if attempt == retries - 1:
                    return {"code": -999, "msg": "Connection failed"}
                await asyncio.sleep(1)
            except Exception as e:
                if attempt == retries - 1:
                    return {"code": -1, "msg": str(e)}
            finally:
                if writer and not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
        return {"code": -999, "msg": "Max retries exceeded"}

    async def get_salt(self, ip: str) -> str:
        if ip in self.salt_cache:
            return self.salt_cache[ip]
        
        response = await self.send_command(ip, {"cmd": "get.device.info", "param": "salt"})
        if response.get('code') == 0:
            self.salt_cache[ip] = response['msg'].get('salt', '')
            return self.salt_cache[ip]
        return ""

    def generate_token(self, cmd: str, salt: str, ts: int) -> str:
        account_pass = ACCOUNTS.get(self.current_account, "")
        raw = f"{cmd}{account_pass}{salt}{ts}".encode()
        return base64.b64encode(hashlib.sha256(raw).digest()).decode()[:8]

    def encrypt_param(self, data: Any, cmd: str, salt: str, ts: int) -> str:
        key = hashlib.sha256(f"{cmd}{ACCOUNTS[self.current_account]}{salt}{ts}".encode()).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        padded = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(iv + encrypted).decode()

    def format_uptime(self, seconds: int) -> str:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        return f"{days}d {hours:02}h {minutes:02}m"

    async def check_connection(self, ip: str) -> bool:
        """Проверить подключение к устройству"""
        try:
            response = await self.send_command(ip, {"cmd": "get.device.info"})
            return response.get('code') == 0
        except Exception as e:
            logging.error(f"{ip}: Ошибка проверки подключения: {str(e)}")
            return False

    def validate_ip(self, ip: str) -> bool:
        """Валидировать IP адрес"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def validate_frequency(self, freq: int) -> bool:
        """Валидировать значение частоты"""
        return 50 <= freq <= 100

    def validate_voltage(self, voltage: int) -> bool:
        """Валидировать значение напряжения"""
        return 700 <= voltage <= 1000

    def validate_power(self, power: int) -> bool:
        """Валидировать значение мощности"""
        return 100 <= power <= 3000  # Для M50S

    async def cleanup(self):
        self.monitor_running = False
        for task in self.active_tasks:
            task.cancel()
        await asyncio.gather(*self.active_tasks, return_exceptions=True)
        logging.info("Мониторинг завершен")

    async def _show_power_menu(self, stdscr):
        menu_items = [
            ("1", "Нормальный режим", "normal"),
            ("2", "Экономичный режим", "low"),
            ("3", "Высокопроизводительный", "high"),
            ("q", "Назад", None)
        ]
        
        h, w = stdscr.getmaxyx()
        self._draw_menu(stdscr, "РЕЖИМЫ ПИТАНИЯ:", menu_items, h//2-3, w//2-15)
        
        while True:
            key = stdscr.getch()
            if key == ord('1'):
                await self.set_power_mode("normal")
                break
            elif key == ord('2'):
                await self.set_power_mode("low")
                break
            elif key == ord('3'):
                await self.set_power_mode("high")
                break
            elif key in [ord('q'), 27]:
                break

    async def _set_power_limit_dialog(self, stdscr):
        h, w = stdscr.getmaxyx()
        win = curses.newwin(5, 40, h//2-2, w//2-20)
        win.border()
        win.addstr(1, 2, "Лимит мощности (100-3000W):")
        curses.echo()
        win.refresh()
        
        try:
            power = int(self._get_input(win, 2, 2, 10))
            if self.validate_power(power):
                await self.set_power_limit(power)
            else:
                logging.error(f"Некорректная мощность: {power}. Допустимый диапазон: 100-3000W")
        except (ValueError, ValidationError) as e:
            logging.error(f"Ошибка при установке лимита мощности: {str(e)}")
        finally:
            curses.noecho()

    async def _set_pools_dialog(self, stdscr):
        h, w = stdscr.getmaxyx()
        win = curses.newwin(12, 70, h//2-6, w//2-35)
        win.border()
        win.addstr(1, 2, "Настройка пулов майнинга (введите 3 пула):")
        
        pools = []
        try:
            curses.echo()
            for i in range(3):
                win.addstr(3+i*3, 2, f"Пул {i+1}:")
                win.addstr(4+i*3, 2, "URL: ")
                url = self._get_input(win, 4+i*3, 7, 50)
                win.addstr(5+i*3, 2, "Рабочий: ")
                worker = self._get_input(win, 5+i*3, 11, 30)
                win.addstr(6+i*3, 2, "Пароль: ")
                password = self._get_input(win, 6+i*3, 10, 30)
                
                pools.append({
                    "pool": url,
                    "worker": worker,
                    "passwd": password
                })
            win.refresh()
        finally:
            curses.noecho()
        
        if pools and pools[0]['pool']:  # Проверяем что хотя бы первый пул заполнен
            await self.set_pools(pools)

    async def _set_frequency_dialog(self, stdscr):
        """Диалог для установки частоты"""
        h, w = stdscr.getmaxyx()
        win = curses.newwin(5, 40, h//2-2, w//2-20)
        win.border()
        win.addstr(1, 2, "Частота (50-100%):")
        curses.echo()
        win.refresh()
        
        try:
            freq = int(self._get_input(win, 2, 2, 10))
            if self.validate_frequency(freq):
                await self.set_frequency(freq)
            else:
                logging.error(f"Некорректная частота: {freq}. Допустимый диапазон: 50-100%")
        except (ValueError, ValidationError) as e:
            logging.error(f"Ошибка при установке частоты: {str(e)}")
        finally:
            curses.noecho()

    async def _set_voltage_dialog(self, stdscr):
        """Диалог для установки напряжения"""
        h, w = stdscr.getmaxyx()
        win = curses.newwin(5, 40, h//2-2, w//2-20)
        win.border()
        win.addstr(1, 2, "Напряжение (700-1000 мВ):")
        curses.echo()
        win.refresh()
        
        try:
            voltage = int(self._get_input(win, 2, 2, 10))
            if self.validate_voltage(voltage):
                await self.set_voltage(voltage)
            else:
                logging.error(f"Некорректное напряжение: {voltage}. Допустимый диапазон: 700-1000 мВ")
        except (ValueError, ValidationError) as e:
            logging.error(f"Ошибка при установке напряжения: {str(e)}")
        finally:
            curses.noecho()

    async def _get_logs_dialog(self, stdscr):
        """Диалог для получения логов"""
        if self.selected_devices:
            ip = list(self.selected_devices)[0]
            logs = await self.get_system_logs(ip, lines=50)
            
            h, w = stdscr.getmaxyx()
            win = curses.newwin(h-4, w-2, 2, 1)
            win.border()
            
            for i, log in enumerate(logs[:h-6]):
                try:
                    win.addstr(1+i, 1, str(log)[:w-4], curses.color_pair(7))
                except curses.error:
                    pass
            
            win.addstr(h-3, 1, "[Нажмите любую клавишу для возврата]")
            win.refresh()
            win.getch()

    async def _show_hashboard_info(self):
        """Показать информацию о хеш-платах"""
        if not self.selected_devices:
            return
        
        for ip in self.selected_devices:
            info = await self.get_hashboard_info(ip)
            temps = await self.get_chip_temperatures(ip)
            logging.info(f"{ip}: Информация о хеш-платах: {json.dumps(info, ensure_ascii=False)}")
            if temps:
                logging.info(f"{ip}: Температуры чипов: {json.dumps(temps, ensure_ascii=False)}")

    async def _backup_config_dialog(self, stdscr):
        """Диалог для резервной копии конфигурации"""
        if not self.selected_devices:
            return
        
        for ip in self.selected_devices:
            await self.backup_configuration(ip)

    async def _change_password_dialog(self, stdscr):
        """Диалог для изменения пароля"""
        h, w = stdscr.getmaxyx()
        win = curses.newwin(5, 50, h//2-2, w//2-25)
        win.border()
        win.addstr(1, 2, "Введите новый пароль:")
        curses.echo()
        win.refresh()
        
        try:
            password = self._get_input(win, 2, 2, 40)
            if password:
                await self.change_password(password)
        finally:
            curses.noecho()

    async def set_pools(self, pools: List[Dict]):
        if not self.selected_devices:
            return

        for ip in self.selected_devices:
            salt = await self.get_salt(ip)
            ts = int(time.time())
            encrypted_param = self.encrypt_param(pools, "set.miner.pools", salt, ts)
            
            response = await self.send_command(ip, {
                "cmd": "set.miner.pools",
                "ts": ts,
                "token": self.generate_token("set.miner.pools", salt, ts),
                "account": self.current_account,
                "param": encrypted_param
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Пулы успешно обновлены")
            else:
                logging.error(f"{ip}: Ошибка обновления пулов")

    def _draw_menu(self, stdscr, title, items, y, x):
        h = len(items) + 4
        w = max(len(title)+2, max(len(i[1]) for i in items)+10)
        win = curses.newwin(h, w, y, x)
        win.border()
        win.addstr(1, 2, title, curses.A_BOLD)
        
        for i, (key, text, _) in enumerate(items):
            win.addstr(2+i, 2, f"[{key}] {text}")
        
        win.refresh()

    def _get_input(self, win, y, x, max_len):
        win.move(y, x)
        win.clrtoeol()
        input_str = ""
        while True:
            ch = win.getch()
            if ch == curses.KEY_ENTER or ch in [10, 13]:
                break
            elif ch == curses.KEY_BACKSPACE or ch == 127:
                input_str = input_str[:-1]
            elif len(input_str) < max_len and 32 <= ch <= 126:
                input_str += chr(ch)
            win.addstr(y, x, input_str.ljust(max_len))
        return input_str.strip()

    async def set_power_mode(self, mode: str):
        if not self.selected_devices:
            return

        for ip in self.selected_devices:
            salt = await self.get_salt(ip)
            ts = int(time.time())
            response = await self.send_command(ip, {
                "cmd": "set.miner.power_mode",
                "ts": ts,
                "token": self.generate_token("set.miner.power_mode", salt, ts),
                "account": self.current_account,
                "param": mode
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Режим питания изменен на {mode}")
            else:
                logging.error(f"{ip}: Ошибка изменения режима питания")

    async def set_power_limit(self, power: int):
        if not self.selected_devices:
            return

        if not self.validate_power(power):
            logging.error(f"Неверное значение мощности {power}. Допустимый диапазон: 100-3000W")
            raise ValidationError(f"Неверное значение мощности: {power}")

        for ip in self.selected_devices:
            salt = await self.get_salt(ip)
            ts = int(time.time())
            response = await self.send_command(ip, {
                "cmd": "set.miner.power_limit",
                "ts": ts,
                "token": self.generate_token("set.miner.power_limit", salt, ts),
                "account": self.current_account,
                "param": power
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Лимит питания установлен на {power}W")
            else:
                logging.error(f"{ip}: Ошибка установки лимита питания")

    async def factory_reset(self):
        if not self.selected_devices:
            return

        for ip in self.selected_devices:
            salt = await self.get_salt(ip)
            ts = int(time.time())
            response = await self.send_command(ip, {
                "cmd": "set.system.factory_reset",
                "ts": ts,
                "token": self.generate_token("set.system.factory_reset", salt, ts),
                "account": self.current_account
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Сброс к заводским настройкам выполнен")
            else:
                logging.error(f"{ip}: Ошибка сброса настроек")

    # ============== НОВЫЕ ФУНКЦИИ ДЛЯ WHATSMINER M50S ==============

    async def get_chip_temperatures(self, ip: str) -> Dict:
        """Получить температуры отдельных чипов"""
        try:
            response = await self.send_command(ip, {
                "cmd": "get.miner.status",
                "param": "chip"
            })
            if response.get('code') == 0:
                return response.get('msg', {})
            logging.error(f"{ip}: Ошибка получения температур чипов")
            return {}
        except Exception as e:
            logging.error(f"{ip}: Ошибка получения температур чипов: {str(e)}")
            return {}

    async def get_hashboard_info(self, ip: str) -> Dict:
        """Получить информацию о хеш-платах"""
        try:
            response = await self.send_command(ip, {
                "cmd": "get.miner.status",
                "param": "hashboard"
            })
            if response.get('code') == 0:
                return response.get('msg', {})
            logging.error(f"{ip}: Ошибка получения информации о хеш-платах")
            return {}
        except Exception as e:
            logging.error(f"{ip}: Ошибка получения информации о хеш-платах: {str(e)}")
            return {}

    async def set_frequency(self, frequency: int) -> bool:
        """Установить частоту майнинга (в процентах от базовой)"""
        if not self.selected_devices:
            return False

        if not self.validate_frequency(frequency):
            logging.error(f"Неверная частота {frequency}. Допустимый диапазон: 50-100%")
            raise ValidationError(f"Неверная частота: {frequency}")

        success_count = 0
        for ip in self.selected_devices:
            try:
                salt = await self.get_salt(ip)
                ts = int(time.time())
                response = await self.send_command(ip, {
                    "cmd": "set.miner.target_freq",
                    "ts": ts,
                    "token": self.generate_token("set.miner.target_freq", salt, ts),
                    "account": self.current_account,
                    "param": frequency
                })
                if response.get('code') == 0:
                    logging.info(f"{ip}: Частота установлена на {frequency}%")
                    success_count += 1
                else:
                    logging.error(f"{ip}: Ошибка установки частоты: {response.get('msg')}")
            except Exception as e:
                logging.error(f"{ip}: Ошибка установки частоты: {str(e)}")

        return success_count > 0

    async def set_voltage(self, voltage: int) -> bool:
        """Установить напряжение (в милливольтах)"""
        if not self.selected_devices:
            return False

        if not self.validate_voltage(voltage):
            logging.error(f"Неверное напряжение {voltage}. Допустимый диапазон: 700-1000 мВ")
            raise ValidationError(f"Неверное напряжение: {voltage}")

        success_count = 0
        for ip in self.selected_devices:
            try:
                salt = await self.get_salt(ip)
                ts = int(time.time())
                response = await self.send_command(ip, {
                    "cmd": "set.miner.voltage",
                    "ts": ts,
                    "token": self.generate_token("set.miner.voltage", salt, ts),
                    "account": self.current_account,
                    "param": voltage
                })
                if response.get('code') == 0:
                    logging.info(f"{ip}: Напряжение установлено на {voltage} мВ")
                    success_count += 1
                else:
                    logging.error(f"{ip}: Ошибка установки напряжения: {response.get('msg')}")
            except Exception as e:
                logging.error(f"{ip}: Ошибка установки напряжения: {str(e)}")

        return success_count > 0

    async def get_system_logs(self, ip: str, lines: int = 100) -> List[str]:
        """Получить логи системы"""
        try:
            response = await self.send_command(ip, {
                "cmd": "get.system.logs",
                "param": {"count": lines}
            })
            if response.get('code') == 0:
                logs = response.get('msg', {}).get('logs', [])
                logging.info(f"{ip}: Получено {len(logs)} строк логов")
                return logs
            logging.error(f"{ip}: Ошибка получения логов")
            return []
        except Exception as e:
            logging.error(f"{ip}: Ошибка получения логов: {str(e)}")
            return []

    async def reset_statistics(self) -> bool:
        """Сброс статистики майнинга"""
        if not self.selected_devices:
            return False

        success_count = 0
        for ip in self.selected_devices:
            try:
                salt = await self.get_salt(ip)
                ts = int(time.time())
                response = await self.send_command(ip, {
                    "cmd": "set.system.reset_statistics",
                    "ts": ts,
                    "token": self.generate_token("set.system.reset_statistics", salt, ts),
                    "account": self.current_account
                })
                if response.get('code') == 0:
                    logging.info(f"{ip}: Статистика сброшена")
                    success_count += 1
                else:
                    logging.error(f"{ip}: Ошибка сброса статистики")
            except Exception as e:
                logging.error(f"{ip}: Ошибка сброса статистики: {str(e)}")

        return success_count > 0

    async def backup_configuration(self, ip: str, filename: str = None) -> bool:
        """Создать резервную копию конфигурации"""
        try:
            if filename is None:
                filename = f"config_backup_{ip}_{int(time.time())}.json"

            response = await self.send_command(ip, {
                "cmd": "get.miner.config"
            })
            
            if response.get('code') == 0:
                config_data = response.get('msg', {})
                with open(filename, 'w') as f:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)
                logging.info(f"{ip}: Конфигурация сохранена в {filename}")
                return True
            else:
                logging.error(f"{ip}: Ошибка получения конфигурации")
                return False
        except Exception as e:
            logging.error(f"{ip}: Ошибка создания резервной копии: {str(e)}")
            return False

    async def restore_configuration(self, ip: str, filename: str) -> bool:
        """Восстановить конфигурацию из резервной копии"""
        try:
            if not os.path.exists(filename):
                logging.error(f"Файл конфигурации {filename} не найден")
                return False

            with open(filename, 'r') as f:
                config_data = json.load(f)

            salt = await self.get_salt(ip)
            ts = int(time.time())
            
            # Шифруем конфигурацию если требуется
            encrypted_param = self.encrypt_param(config_data, "set.miner.config", salt, ts)
            
            response = await self.send_command(ip, {
                "cmd": "set.miner.config",
                "ts": ts,
                "token": self.generate_token("set.miner.config", salt, ts),
                "account": self.current_account,
                "param": encrypted_param
            })
            
            if response.get('code') == 0:
                logging.info(f"{ip}: Конфигурация восстановлена")
                return True
            else:
                logging.error(f"{ip}: Ошибка восстановления конфигурации")
                return False
        except Exception as e:
            logging.error(f"{ip}: Ошибка восстановления конфигурации: {str(e)}")
            return False

    async def get_usb_devices_info(self, ip: str) -> List[Dict]:
        """Получить информацию об USB-устройствах"""
        try:
            response = await self.send_command(ip, {
                "cmd": "get.system.usb"
            })
            
            if response.get('code') == 0:
                usb_devices = response.get('msg', {}).get('devices', [])
                logging.info(f"{ip}: Получена информация о {len(usb_devices)} USB-устройствах")
                return usb_devices
            else:
                logging.error(f"{ip}: Ошибка получения информации об USB-устройствах")
                return []
        except Exception as e:
            logging.error(f"{ip}: Ошибка получения информации об USB-устройствах: {str(e)}")
            return []

    async def set_auto_recovery(self, enabled: bool = True) -> bool:
        """Включить/отключить автоматическое восстановление"""
        if not self.selected_devices:
            return False

        success_count = 0
        for ip in self.selected_devices:
            try:
                salt = await self.get_salt(ip)
                ts = int(time.time())
                response = await self.send_command(ip, {
                    "cmd": "set.system.auto_recovery",
                    "ts": ts,
                    "token": self.generate_token("set.system.auto_recovery", salt, ts),
                    "account": self.current_account,
                    "param": 1 if enabled else 0
                })
                if response.get('code') == 0:
                    status = "включено" if enabled else "отключено"
                    logging.info(f"{ip}: Автоматическое восстановление {status}")
                    success_count += 1
                else:
                    logging.error(f"{ip}: Ошибка установки автоматического восстановления")
            except Exception as e:
                logging.error(f"{ip}: Ошибка установки автоматического восстановления: {str(e)}")

        return success_count > 0

    async def get_performance_stats(self, ip: str) -> Dict:
        """Получить расширенную статистику производительности"""
        try:
            response = await self.send_command(ip, {
                "cmd": "get.miner.status",
                "param": "performance"
            })
            
            if response.get('code') == 0:
                return response.get('msg', {})
            else:
                logging.error(f"{ip}: Ошибка получения статистики производительности")
                return {}
        except Exception as e:
            logging.error(f"{ip}: Ошибка получения статистики производительности: {str(e)}")
            return {}

    async def change_password(self, new_password: str) -> bool:
        """Изменить пароль аккаунта"""
        if not self.selected_devices or not new_password:
            return False

        success_count = 0
        for ip in self.selected_devices:
            try:
                salt = await self.get_salt(ip)
                ts = int(time.time())
                
                encrypted_pass = self.encrypt_param(
                    new_password,
                    "set.user.change_passwd",
                    salt,
                    ts
                )
                
                response = await self.send_command(ip, {
                    "cmd": "set.user.change_passwd",
                    "ts": ts,
                    "token": self.generate_token("set.user.change_passwd", salt, ts),
                    "account": self.current_account,
                    "param": encrypted_pass
                })
                
                if response.get('code') == 0:
                    logging.info(f"{ip}: Пароль успешно изменен")
                    success_count += 1
                else:
                    logging.error(f"{ip}: Ошибка изменения пароля: {response.get('msg')}")
            except Exception as e:
                logging.error(f"{ip}: Ошибка изменения пароля: {str(e)}")

        return success_count > 0

    async def enable_thermal_throttling(self, enabled: bool = True) -> bool:
        """Включить/отключить тепловое ограничение"""
        if not self.selected_devices:
            return False

        success_count = 0
        for ip in self.selected_devices:
            try:
                salt = await self.get_salt(ip)
                ts = int(time.time())
                response = await self.send_command(ip, {
                    "cmd": "set.system.thermal_throttling",
                    "ts": ts,
                    "token": self.generate_token("set.system.thermal_throttling", salt, ts),
                    "account": self.current_account,
                    "param": 1 if enabled else 0
                })
                if response.get('code') == 0:
                    status = "включено" if enabled else "отключено"
                    logging.info(f"{ip}: Тепловое ограничение {status}")
                    success_count += 1
                else:
                    logging.error(f"{ip}: Ошибка установки теплового ограничения")
            except Exception as e:
                logging.error(f"{ip}: Ошибка установки теплового ограничения: {str(e)}")

        return success_count > 0

async def scan_network(network: str) -> List[str]:
    nm = nmap.PortScanner()
    print(f"Сканирование {network}...")
    await asyncio.to_thread(nm.scan, network, arguments=f'-p {API_PORT} --open')
    devices = [host for host in nm.all_hosts() if nm[host]['tcp'][API_PORT]['state'] == 'open']
    with open(CONFIG_FILE, 'w') as f:
        json.dump(devices, f)
    print(f"Найдено устройств: {len(devices)}")
    return devices

def load_devices() -> List[str]:
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        logging.error(f"Ошибка загрузки устройств: {str(e)}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Мониторинг ASIC-устройств")
    parser.add_argument("--scan", help="Диапазон сети для сканирования")
    parser.add_argument("--firmware", default=DEFAULT_FIRMWARE, help="Путь к файлу прошивки")
    args = parser.parse_args()

    if not args.scan and not os.path.exists(CONFIG_FILE):
        print("Необходимо указать --scan для первого запуска")
        return

    devices = asyncio.run(scan_network(args.scan)) if args.scan else load_devices()
    monitor = DeviceMonitor(devices)
    monitor.firmware_path = args.firmware

    def curses_main(stdscr):
        try:
            asyncio.run(monitor.monitor(stdscr))
        except KeyboardInterrupt:
            logging.info("Завершено пользователем")

    curses.wrapper(curses_main)

if __name__ == "__main__":
    main()
