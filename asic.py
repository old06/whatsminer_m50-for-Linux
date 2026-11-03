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
import ipaddress
from logging.handlers import TimedRotatingFileHandler
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from dotenv import load_dotenv
import argparse
from typing import Dict, List, Set, Tuple, Optional, Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

CONFIG_FILE = os.path.join(BASE_DIR, "asic_devices.json")
LOG_FILE = os.path.join(BASE_DIR, "asic_monitor.log")
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
MAX_SCAN_ADDRESSES = 65536
COMMAND_RETRIES = 3
CONNECTION_TIMEOUT = 15
READ_TIMEOUT = 50
CHUNK_SIZE = 4096
DEFAULT_FIRMWARE = os.path.join(BASE_DIR, "firmware.bin")
ENCRYPTED_COMMANDS = {'set.miner.pools', 'set.user.change_passwd', 'set.miner.power_percent'}
OVERHEAT_TEMP = 80  # Температура перегрева
ERROR_CODE_INFO = {
    "110": ("Ошибка скорости входного вентилятора", 10),
    "111": ("Ошибка скорости выходного вентилятора", 10),
    "120": ("Отклонение скорости входного вентилятора >2000", 3),
    "121": ("Отклонение скорости выходного вентилятора >2000", 3),
    "130": ("Отклонение скорости входного вентилятора >3000", 3),
    "131": ("Отклонение скорости выходного вентилятора >3000", 3),
    "140": ("Слишком высокая скорость вентилятора", 0),
    "200": ("Не обнаружено питание", 10),
    "201": ("Блок питания не соответствует конфигурации", 10),
    "202": ("Ошибка выходного напряжения БП", 10),
    "203": ("Защита питания", 10),
    "204": ("Защита по току питания", 10),
    "205": ("Ошибка тока питания", 10),
    "206": ("Низкое входное напряжение", 10),
    "207": ("Защита по входному току", 10),
    "208": ("Нестабильная работа БП", 10),
    "209": ("Резкое отклонение напряжения БП", 10),
    "210": ("Ошибка состояния БП", 10),
    "211": ("Большое отклонение выходного тока", 0),
    "212": ("Недостаточный запас выходного напряжения", 3),
    "213": ("Несоответствие входного напряжения и тока", 0),
    "214": ("Не изменился контакт питания", 10),
    "215": ("Ошибка установки выходного напряжения БП", 10),
    "216": ("Питание долго не менялось", 10),
    "217": ("Ошибка включения питания", 10),
    "218": ("Входное напряжение ниже 230 В в мощном режиме", 2),
    "219": ("Некорректный входной ток", 10),
    "233": ("Перегрев выхода БП", 10),
    "234": ("Перегрев выхода БП", 10),
    "235": ("Перегрев выхода БП", 10),
    "236": ("Защита выхода БП от перегрузки по току", 10),
    "237": ("Защита выхода БП от перегрузки по току", 10),
    "238": ("Защита выхода БП от перегрузки по току", 10),
    "239": ("Перенапряжение на выходе БП", 10),
    "240": ("Низкое напряжение на выходе БП", 10),
    "241": ("Дисбаланс выходного тока БП", 10),
    "243": ("Перегрев входа БП", 10),
    "244": ("Перегрев входа БП", 10),
    "245": ("Перегрев входа БП", 10),
    "246": ("Перегрузка по входному току БП", 10),
    "247": ("Перегрузка по входному току БП", 10),
    "248": ("Перенапряжение на входе БП", 10),
    "249": ("Перенапряжение на входе БП", 10),
    "250": ("Низкое напряжение на входе БП", 10),
    "251": ("Низкое напряжение на входе БП", 10),
    "253": ("Ошибка вентилятора БП", 10),
    "254": ("Ошибка вентилятора БП", 10),
    "255": ("Превышена выходная мощность БП", 10),
    "256": ("Превышена выходная мощность БП", 10),
    "257": ("Защита первичной цепи БП от перегрузки", 10),
    "258": ("Дисбаланс фазного напряжения БП", 10),
    "259": ("Защита от дисбаланса фазного напряжения", 10),
    "260": ("Дисбаланс фазного тока БП", 10),
    "261": ("Защита от дисбаланса фазного тока", 10),
    "263": ("Предупреждение о связи с БП", 10),
    "264": ("Ошибка связи с БП", 10),
    "267": ("Защита watchdog блока питания", 10),
    "268": ("Защита выхода БП от сверхтока", 3),
    "269": ("Защита входа БП от сверхтока", 3),
    "270": ("Защита БП от входного перенапряжения", 3),
    "271": ("Защита БП от низкого входного напряжения", 3),
    "272": ("Предупреждение о высокой выходной мощности БП", 3),
    "273": ("Предупреждение о высокой входной мощности", 3),
    "274": ("Предупреждение о вентиляторе БП", 0),
    "275": ("Предупреждение о перегреве БП", 0),
    "300": ("Ошибка датчика температуры хеш-платы", 10),
    "309": ("Не работают датчики температуры", None),
    "320": ("Ошибка чтения температуры хеш-платы", 10),
    "326": ("Ошибка датчика температуры жидкостного охлаждения", None),
    "329": ("Ошибка датчика температуры контроллера", None),
    "350": ("Защита по температуре хеш-платы", 10),
    "360": ("Перегрев хеш-платы", 10),
    "370": ("Сильные колебания температуры окружающей среды", 3),
    "410": ("Ошибка чтения EEPROM хеш-платы", 10),
    "420": ("Ошибка разбора EEPROM хеш-платы", 10),
    "430": ("Несовпадение типа чипов", 10),
    "440": ("Ошибка количества чипов в EEPROM", 10),
    "450": ("Ошибка передачи данных EEPROM", 10),
    "500": ("Нет конфигурации ПО для модели", 10),
    "510": ("Ошибка типа майнера хеш-платы", 10),
    "520": ("Несовпадение типа чипов хеш-платы", 10),
    "530": ("Хеш-плата не обнаружена", 10),
    "540": ("Ошибка чтения ID чипа", 10),
    "550": ("Обнаружены неисправные чипы", 10),
    "560": ("Ошибка балансировки хеш-платы", 10),
    "570": ("Ошибка передачи данных чипа", 10),
    "580": ("Ошибка сброса чипа", 0),
    "590": ("Слишком низкая частота чипов", 5),
    "600": ("Высокая температура окружающей среды", 10),
    "610": ("Для режима высокой мощности слишком жарко", 3),
    "620": ("Защита по температуре охлаждающей жидкости", 7),
    "652": ("Сильные колебания температуры жидкости", 4),
    "701": ("Контроллер не поддерживает чип", 10),
    "702": ("Неизвестная версия контроллера", 10),
    "710": ("Аварийная перезагрузка контроллера", 10),
    "712": ("Аварийная перезагрузка контроллера", 3),
    "714": ("Серьезная нестабильность сети", 10),
    "720": ("Ошибка связи с хеш-платой", 10),
    "800": ("Ошибка контрольной суммы cgminer", 10),
    "801": ("Ошибка контрольной суммы system-monitor", 10),
    "802": ("Ошибка контрольной суммы remote-daemon", 10),
    "810": ("Несоответствие режима охлаждения/частоты", 10),
    "820": ("Несоответствие режима охлаждения/БП", 10),
    "901": ("Ошибка коэффициента мощности", 5),
    "9000": ("Процесс завершился аварийно", 0),
    "2000": ("Не настроены пулы", 10),
    "2010": ("Все пулы отключены", 10),
    "2020": ("Не удалось подключиться к пулу", 10),
    "2030": ("Высокий процент отклоненных шар", 10),
    "2040": ("Пул не поддерживает ASICBoost", 10),
    "2050": ("Не удалось переключиться на новый пул", 10),
    "2310": ("Слишком низкий хешрейт", 10),
    "2320": ("Слишком низкий хешрейт", 2),
    "2340": ("Слишком большая потеря хешрейта", 1),
    "2350": ("Слишком большая потеря хешрейта", 10),
    "5010": ("Слишком низкое напряжение чипа", 0),
    "5020": ("Изменилось напряжение чипа", 0),
    "5030": ("Большой разброс температур чипов", 0),
    "5040": ("Большой разброс максимальных температур чипов", 2),
    "5050": ("Защита чипов по температуре", 10),
    "5070": ("Ненормальная скорость потока жидкости", 10),
    "5079": ("Слишком медленный поток жидкости", 10),
    "5080": ("Ошибка калибровки температуры чипа", 0),
    "5090": ("Ошибка калибровки температуры чипа", 0),
    "5110": ("Тайм-аут повышения частоты", 10),
    "6030": ("Защита чипов от перегрева", 10),
    "8000": ("Устаревшая версия WhatsMinerTool", 0),
    "8010": ("Частота ниже нормы", 0),
    "8020": ("Хешрейт ниже нормы", 0),
    "8400": ("Неверная или неофициальная версия ПО", 0),
    "8410": ("Прошивка не соответствует модели майнера", 10),
    "8700": ("Модель майнера не соответствует модели БП", 10),
    "100000": ("Ошибка библиотеки безопасности", 10),
    "100001": ("Нарушена подпись системного файла", 10),
    "100002": ("Нарушен системный файл antiv/dig/initd.dig", 10),
    "100003": ("Нарушен системный файл antiv/dig/pf_partial.dig", 10),
    "100100": ("Удален системный btminer", 10),
    "110000": ("Обнаружен неразрешенный системный файл", 10),
    "110001": ("Обнаружено удаление файла безопасности", 10),
}
ERROR_CODE_PATTERNS = (
    ("28", ("Ошибка пользовательского регистра БП", 0)),
    ("30", ("Ошибка датчика температуры хеш-платы", 10)),
    ("32", ("Ошибка чтения температуры хеш-платы", 10)),
    ("35", ("Защита по температуре хеш-платы", 10)),
    ("41", ("Ошибка чтения EEPROM хеш-платы", 10)),
    ("42", ("Ошибка разбора EEPROM хеш-платы", 10)),
    ("43", ("Несовпадение типа чипов", 10)),
    ("44", ("Ошибка количества чипов в EEPROM", 10)),
    ("45", ("Ошибка передачи данных EEPROM", 10)),
    ("51", ("Ошибка типа майнера хеш-платы", 10)),
    ("52", ("Несовпадение типа чипов хеш-платы", 10)),
    ("53", ("Хеш-плата не обнаружена", 10)),
    ("54", ("Ошибка чтения ID чипа", 10)),
    ("55", ("Обнаружены неисправные чипы", 10)),
    ("56", ("Ошибка балансировки хеш-платы", 10)),
    ("57", ("Ошибка передачи данных чипа", 10)),
    ("58", ("Ошибка сброса чипа", 0)),
    ("59", ("Слишком низкая частота чипов", 5)),
    ("72", ("Ошибка связи с хеш-платой", 10)),
    ("90", ("Процесс завершился аварийно", 0)),
    ("501", ("Слишком низкое напряжение чипа", 0)),
    ("502", ("Изменилось напряжение чипа", 0)),
    ("503", ("Большой разброс температур чипов", 0)),
    ("504", ("Большой разброс максимальных температур чипов", 2)),
    ("505", ("Защита чипов по температуре", 10)),
    ("507", ("Ненормальная скорость потока жидкости", 10)),
    ("508", ("Ошибка калибровки температуры чипа", 0)),
    ("511", ("Тайм-аут повышения частоты", 10)),
    ("603", ("Защита чипов от перегрева", 10)),
)
PSU_ERROR_INFO = {
    "0x0001": ("Низкое входное напряжение БП", False),
    "0x0002": ("Защита радиатора БП от перегрева", True),
    "0x0004": ("Защита радиатора БП от перегрева", True),
    "0x0008": ("Защита БП от высокой температуры окружающей среды", True),
    "0x0010": ("Защита первичной цепи БП от сверхтока", True),
    "0x0020": ("Пониженное выходное напряжение БП", True),
    "0x0040": ("Защита выхода БП от сверхтока", True),
    "0x0080": ("Защита первичной цепи БП от сверхтока", True),
    "0x0100": ("Сверхток в одной из цепей БП", True),
    "0x0200": ("Сверхток в одной из цепей БП", True),
    "0x0400": ("Сверхток в одной из цепей БП", True),
    "0x0800": ("Отказ вентилятора БП", True),
    "0x1000": ("Длительная защита выхода БП от сверхтока", True),
    "0x2000": ("Длительная защита выхода БП от сверхтока", True),
}
ERROR_FIELD_NAMES = {
    "error", "errors", "errorcode", "errorcodes", "fault", "faults",
    "faultcode", "faultcodes", "alarm", "alarms", "alarmcode",
    "alarmcodes", "errcode", "errcodes",
}

def configure_logging():
    logger = logging.getLogger()
    if not any(
        isinstance(handler, TimedRotatingFileHandler)
        and handler.baseFilename == LOG_FILE
        for handler in logger.handlers
    ):
        handler = TimedRotatingFileHandler(
            LOG_FILE,
            when="midnight",
            interval=1,
            backupCount=7,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        ))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)

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
        self.salt_cache: Dict[str, str] = {}
        self.stats_cache = {"all_devices": []}
        self.operation_queue = None
        self.pending_operation_devices: Set[str] = set()
        self.operation_progress: Dict[str, Tuple] = {}
        self.firmware_path = DEFAULT_FIRMWARE
        self.lock = None
        self.api_semaphore = asyncio.Semaphore(MAX_CONCURRENT_OPS)
        self.restarting_devices: Set[str] = set()
        self.detailed_view = False  # Режим детального просмотра устройства
        
    async def _init_async_resources(self):
        if self.operation_queue is None:
            self.operation_queue = asyncio.Queue()
        if self.lock is None:
            self.lock = asyncio.Lock()
        if not self.active_tasks:
            self.active_tasks.update({
                asyncio.create_task(self._update_progress_bars()),
                asyncio.create_task(self._update_stats())
            })
            self.active_tasks.update(
                asyncio.create_task(
                    self._process_operations(),
                    name=f"operation-worker-{index}",
                )
                for index in range(MAX_CONCURRENT_OPS)
            )

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
                self._handle_key_down(stdscr)
            elif key == ord(' '):
                self._toggle_device_selection()
            elif key == ord('a'):
                self._toggle_all_devices()
            elif key == ord('r'):
                await self.reboot_devices()
            elif key == ord('u'):
                if await self._confirm_action(
                    stdscr,
                    "Upload firmware to "
                    f"{len(self.selected_devices)} device(s)? [y/N]",
                ):
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
                if await self._confirm_action(
                    stdscr,
                    "Factory reset "
                    f"{len(self.selected_devices)} device(s)? [y/N]",
                ):
                    await self.factory_reset()
            elif key == ord('C'):
                await self._set_frequency_dialog(stdscr)
            key = stdscr.getch()

    async def _confirm_action(self, stdscr, prompt: str) -> bool:
        h, _ = stdscr.getmaxyx()
        self._safe_addstr(stdscr, max(0, h - 2), 0, prompt, curses.A_REVERSE)
        stdscr.refresh()
        while self.monitor_running:
            key = stdscr.getch()
            if key in (ord('y'), ord('Y')):
                return True
            if key in (ord('n'), ord('N'), 27):
                return False
            await asyncio.sleep(MONITOR_INTERVAL)
        return False

    def _handle_key_up(self):
        if self.current_row > 0:
            self.current_row -= 1
            if self.current_row < self.scroll_offset:
                self.scroll_offset = self.current_row

    def _handle_key_down(self, stdscr):
        valid_data = self._get_sorted_devices()
        total_items = len(valid_data)
        h, _ = stdscr.getmaxyx()
        max_visible_rows = max(1, h - 8)
        
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

    def _error_info(self, code: str) -> Tuple[str, Optional[int]]:
        if code in PSU_ERROR_INFO:
            return PSU_ERROR_INFO[code][0], None
        if code in ERROR_CODE_INFO:
            return ERROR_CODE_INFO[code]
        for prefix, info in ERROR_CODE_PATTERNS:
            if code.startswith(prefix):
                return info
        return "Неизвестный код ошибки", None

    def _normalize_error_code(self, value: Any) -> Optional[str]:
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value) if value > 0 else None
        if not isinstance(value, str):
            return None

        candidate = value.strip()
        if candidate.lower().startswith("0x"):
            try:
                return f"0x{int(candidate, 16):04x}"
            except ValueError:
                return None
        if candidate.isdigit() and int(candidate) > 0:
            return str(int(candidate))
        return None

    def _error_codes_in_value(self, value: Any) -> List[str]:
        codes = []
        if isinstance(value, dict):
            for key, nested_value in value.items():
                normalized_key = str(key).lower().replace("_", "").replace("-", "")
                if normalized_key in {"code", "id", "errorcode", "errcode"}:
                    codes.extend(self._error_codes_in_value(nested_value))
                elif self._normalize_error_code(str(key)):
                    codes.append(self._normalize_error_code(str(key)))
                elif isinstance(nested_value, (dict, list, tuple)):
                    codes.extend(self._error_codes_in_value(nested_value))
        elif isinstance(value, (list, tuple)):
            for item in value:
                codes.extend(self._error_codes_in_value(item))
        else:
            code = self._normalize_error_code(value)
            if code:
                codes.append(code)
        return codes

    def _error_reasons_in_value(self, value: Any) -> Dict[str, str]:
        reasons = {}
        if isinstance(value, dict):
            reason = next((
                str(item).strip()
                for key, item in value.items()
                if str(key).lower() in {"reason", "message", "description"}
                and item
            ), "")
            for key, nested_value in value.items():
                code = self._normalize_error_code(str(key))
                if code and reason:
                    reasons[code] = reason
                elif isinstance(nested_value, (dict, list, tuple)):
                    reasons.update(self._error_reasons_in_value(nested_value))
        elif isinstance(value, (list, tuple)):
            for item in value:
                reasons.update(self._error_reasons_in_value(item))
        return reasons

    def _extract_device_errors(self, *responses: Dict) -> List[Dict[str, Any]]:
        found_reasons = {}
        found_codes = []

        def visit(value):
            if isinstance(value, dict):
                for key, nested_value in value.items():
                    normalized_key = (
                        str(key).lower().replace("_", "").replace("-", "")
                    )
                    if (
                        normalized_key in ERROR_FIELD_NAMES
                        or normalized_key.endswith("error")
                        or normalized_key.endswith("errors")
                        or normalized_key.endswith("fault")
                        or normalized_key.endswith("alarms")
                    ):
                        found_codes.extend(
                            self._error_codes_in_value(nested_value)
                        )
                        found_reasons.update(
                            self._error_reasons_in_value(nested_value)
                        )
                    visit(nested_value)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    visit(item)

        for response in responses:
            visit(response)

        errors = []
        for code in dict.fromkeys(found_codes):
            description, severity = self._error_info(code)
            description = found_reasons.get(code, description)
            critical = (
                severity is not None and severity >= 10
            ) or PSU_ERROR_INFO.get(code, ("", False))[1]
            errors.append({
                "code": code,
                "description": description,
                "severity": severity,
                "critical": critical,
            })
        return errors

    def _has_critical_errors(self, device: Dict) -> bool:
        return any(error.get("critical") for error in device.get("errors", []))

    async def _draw_interface(self, stdscr):
        h, w = stdscr.getmaxyx()
        valid_data = self._get_sorted_devices()
        if valid_data:
            self.current_row = min(self.current_row, len(valid_data) - 1)
            self.scroll_offset = min(
                self.scroll_offset,
                max(0, len(valid_data) - max(1, h - 8)),
            )
        else:
            self.current_row = 0
            self.scroll_offset = 0
        
        if self.detailed_view and valid_data and self.current_row < len(valid_data):
            await self._draw_device_details(stdscr, valid_data[self.current_row], h, w)
            return
            
        online_devices = [d for d in valid_data if d.get('online') and d['ip'] not in self.restarting_devices]
        total_hashrate = sum(d.get('hashrate', 0) for d in online_devices)
        total_power = sum(d.get('power', 0) for d in online_devices)
        avg_temp = sum(d.get('temp', 0) for d in online_devices) / len(online_devices) if online_devices else 0
        online_count = len(online_devices)
        offline_count = len(valid_data) - online_count - len(self.restarting_devices)
        error_count = sum(len(device.get("errors", [])) for device in valid_data)
        error_device_count = sum(bool(device.get("errors")) for device in valid_data)

        stdscr.erase()
        
        header = (
            f"Ошибки: {error_count} ({error_device_count} устройств) | "
            f"Всего: {len(valid_data)} | ON: {online_count} | "
            f"OFF: {offline_count} | RST: {len(self.restarting_devices)}"
        )
        stats = f"Хэшрейт: {total_hashrate:.1f} TH/s | Питание: {total_power/1000:.1f} kW | Темп: {avg_temp:.1f}°C"
        self._safe_addstr(stdscr, 0, 0, header, curses.A_BOLD | curses.color_pair(7))
        self._safe_addstr(stdscr, 1, 0, stats, curses.color_pair(7))
        
        self._draw_devices_list(stdscr, h, w, valid_data)
        self._draw_progress_bars(stdscr, h, w)
        
        help_text = (
            "[Space]Выбор [a]Все [r]Рестарт [u]Прошивка [f]Вент [l]LED "
            "[m]Режим [L]Лимит [P]Пулы [d]Детали [C]Частота [F]Сброс [q]Выход"
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
            self._safe_addstr(stdscr, 3 + i, 0, row, curses.color_pair(7))
        
        error_y = 13
        self._safe_addstr(stdscr, error_y, 0, "-" * (w - 1), curses.color_pair(7))
        error_y += 1
        errors = device.get("errors", [])
        error_title = f"Ошибки устройства: {len(errors)}"
        self._safe_addstr(
            stdscr, error_y, 0, error_title,
            curses.A_BOLD | (curses.color_pair(9) if self._has_critical_errors(device)
                             else curses.color_pair(7))
        )
        error_y += 1
        if errors:
            for error in errors:
                severity = error.get("severity")
                level_text = f" | уровень {severity}" if severity is not None else ""
                error_text = (
                    f"Код {error['code']}: {error['description']}{level_text}"
                )
                error_color = (
                    curses.color_pair(9) if error.get("critical")
                    else curses.color_pair(2)
                )
                self._safe_addstr(stdscr, error_y, 2, error_text, error_color)
                error_y += 1
        else:
            self._safe_addstr(stdscr, error_y, 2, "Нет активных ошибок")
            error_y += 1

        pool_y = error_y + 1
        self._safe_addstr(
            stdscr, pool_y, 0, "Пулы майнинга:",
            curses.A_BOLD | curses.color_pair(7)
        )
        for i, pool in enumerate(device.get('pools', [])[:3]):
            status_color = curses.color_pair(4) if pool.get('status') == 'alive' else curses.color_pair(1)
            pool_text = f"{i+1}. {pool.get('url', 'N/A')}"
            self._safe_addstr(stdscr, pool_y + 1 + i * 2, 2, pool_text, status_color)
            worker_text = f"Worker: {pool.get('worker', 'N/A')} | Status: {pool.get('status', 'N/A')}"
            self._safe_addstr(
                stdscr, pool_y + 2 + i * 2, 4, worker_text,
                curses.color_pair(3)
            )
        
        # Кнопка возврата
        help_text = "[D]Назад [Q]Выход"
        stdscr.addstr(h-1, 0, help_text.ljust(w-1), curses.A_REVERSE)
        stdscr.refresh()

    def _get_sorted_devices(self):
        return sorted(
            [d for d in self.stats_cache["all_devices"] if isinstance(d, dict)],
            key=lambda x: (x.get('online', False), x.get('hashrate', 0)),
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
        max_visible_rows = max(0, h - 8)
        start_row = 3
        columns = self._device_table_columns(w)
        header = " | ".join(
            label[:column_width].center(column_width)
            for label, column_width, _, _ in columns
        )
        self._safe_addstr(stdscr, start_row - 1, 0, header, curses.A_BOLD)
        
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
            
            line = self._format_device_line(device, w, columns)
            self._safe_addstr(stdscr, y, 0, line, color)

    def _device_table_columns(self, width):
        columns = [
            ("STATUS", 8, lambda device: self._get_device_status(device), "<"),
            ("IP", 15, lambda device: device.get("ip", "N/A"), "<"),
            ("ERR", 5, lambda device: len(device.get("errors", [])), ">"),
            ("TEMP C", 8, lambda device: f"{device.get('temp', 0):.1f}", ">"),
            ("HASH TH/s", 10, lambda device: f"{device.get('hashrate', 0):.1f}", ">"),
            ("POWER kW", 9, lambda device: f"{device.get('power', 0) / 1000:.1f}", ">"),
            ("UPTIME", 12, lambda device: device.get("uptime", "N/A"), "<"),
            ("FW", 8, lambda device: device.get("fw_version", "N/A"), "<"),
            ("FREQ %", 7, lambda device: device.get("target_freq", 0), ">"),
            (
                "FANS RPM", 13,
                lambda device: (
                    f"{device.get('fan_in', 0)}/{device.get('fan_out', 0)}"
                ),
                ">",
            ),
        ]
        available_width = max(0, width - 1)
        while len(columns) > 6:
            required_width = sum(column[1] for column in columns) + 3 * (len(columns) - 1)
            if required_width <= available_width:
                break
            columns.pop()

        required_width = sum(column[1] for column in columns) + 3 * (len(columns) - 1)
        if required_width > available_width and len(columns) > 4:
            columns.pop(5)
            columns.pop(4)

        required_width = sum(column[1] for column in columns) + 3 * (len(columns) - 1)
        if required_width > available_width and len(columns) > 2:
            ip_width = max(7, columns[1][1] - (required_width - available_width))
            label, _, value, align = columns[1]
            columns[1] = (label, ip_width, value, align)
        return columns

    def _format_device_line(self, device, width, columns=None):
        columns = columns or self._device_table_columns(width)
        cells = []
        for _, column_width, value_getter, alignment in columns:
            value = str(value_getter(device))[:column_width]
            cells.append(value.rjust(column_width) if alignment == ">"
                         else value.ljust(column_width))
        return " | ".join(cells)

    def _get_device_color(self, device):
        if device['ip'] in self.restarting_devices:
            return curses.color_pair(8)
        if self._has_critical_errors(device):
            return curses.color_pair(9)
        if not device.get('online'):
            return curses.color_pair(1)
        if device.get('temp', 0) > OVERHEAT_TEMP:
            return curses.color_pair(9)
        return curses.color_pair(4)

    def _get_device_status(self, device):
        if device['ip'] in self.restarting_devices:
            return "RST"
        if self._has_critical_errors(device):
            return "CRITICAL"
        error_count = len(device.get("errors", []))
        if error_count:
            return "ERROR"
        if device.get('temp', 0) > OVERHEAT_TEMP:
            return "HOT"
        return "ONLINE" if device.get('online') else "OFFLINE"

    def _draw_progress_bars(self, stdscr, h, w):
        progress_y = h - 4
        for ip, (op_type, start, duration, stage) in self.operation_progress.items():
            if isinstance(stage, str) and stage.startswith("upload "):
                try:
                    progress = float(stage[7:].rstrip("%")) / 100
                except ValueError:
                    progress = 0
            else:
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
        while self.monitor_running:
            ip, operation = await self.operation_queue.get()
            try:
                if operation == "reboot":
                    await self._reboot_device(ip)
                elif operation == "update":
                    await self._update_device(ip)
            finally:
                self.operation_queue.task_done()
                self.pending_operation_devices.discard(ip)

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
            
            status_data = await self.send_command(ip, {
                "cmd": "get.miner.status",
                "param": "summary+pools",
            })
            static_msg = static_data.get('msg', {})
            errors = self._extract_device_errors(static_data)
            status_msg = status_data.get('msg', {})
            if not isinstance(static_msg, dict):
                static_msg = {}
            if not isinstance(status_msg, dict):
                status_msg = {}

            pools = []
            if status_data.get('code') == 0:
                raw_pools = status_msg.get('pools', [])
                for p in raw_pools:
                    pools.append({
                        "url": p.get('pool', p.get('url', 'N/A')),
                        "worker": p.get('worker', 'N/A'),
                        "status": p.get('status', 'N/A'),
                        "passwd": '***' if p.get('passwd') else 'N/A'
                    })
    
            if status_data.get('code') != 0:
                return {"ip": ip, "online": False, "errors": errors}

            summary = status_msg.get('summary', {})
            if not isinstance(summary, dict):
                summary = {}
            
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
                "pools": pools,
                "errors": errors,
            }
        except Exception as e:
            logging.error(f"{ip}: Ошибка получения данных: {str(e)}")
            return {"ip": ip, "online": False}

    async def reboot_devices(self) -> int:
        if not self.selected_devices:
            return 0

        if self.operation_queue is None:
            await self._init_async_resources()
        queued_count = 0
        for ip in sorted(self.selected_devices):
            if ip in self.pending_operation_devices:
                logging.warning(f"{ip}: Операция уже поставлена в очередь")
                continue
            self.pending_operation_devices.add(ip)
            await self.operation_queue.put((ip, "reboot"))
            queued_count += 1
        logging.info(f"Инициирована перезагрузка {queued_count} устройств")
        return queued_count

    async def _reboot_device(self, ip: str):
        try:
            resp = await self.send_command(ip, {
                "cmd": "set.system.reboot",
            })
            if resp.get('code') == 0:
                self.restarting_devices.add(ip)
                self.operation_progress[ip] = ("reboot", time.time(), REBOOT_DURATION, "final")
                logging.info(f"{ip}: Успешная перезагрузка")
            else:
                logging.error(f"{ip}: Ошибка перезагрузки")
        except Exception as e:
            logging.exception(f"{ip}: Ошибка перезагрузки")
        finally:
            if ip in self.restarting_devices:
                try:
                    await asyncio.sleep(REBOOT_DURATION + 5)
                finally:
                    self.restarting_devices.discard(ip)
                await self.force_refresh_device(ip, delay=0)

    async def update_firmware(self) -> int:
        if not self.selected_devices:
            return 0

        if not os.path.isfile(self.firmware_path) or not os.access(self.firmware_path, os.R_OK):
            logging.error(f"Файл прошивки недоступен для чтения: {self.firmware_path}")
            return 0

        if os.path.getsize(self.firmware_path) == 0:
            logging.error(f"Файл прошивки пуст: {self.firmware_path}")
            return 0

        if self.operation_queue is None:
            await self._init_async_resources()
        queued_count = 0
        for ip in sorted(self.selected_devices):
            if ip in self.pending_operation_devices:
                logging.warning(f"{ip}: Операция уже поставлена в очередь")
                continue
            self.pending_operation_devices.add(ip)
            await self.operation_queue.put((ip, "update"))
            queued_count += 1
        logging.info(f"Инициировано обновление {queued_count} устройств")
        return queued_count
    async def _update_device(self, ip: str):
        writer = None
        firmware_file = None
        api_slot_acquired = False
        previous_fw_version = None
        try:
            if not ACCOUNTS.get(self.current_account):
                raise ValidationError(
                    f"Password for account {self.current_account!r} "
                    "is not configured"
                )
            device_before = await self.get_device_data(ip)
            if device_before.get("online"):
                previous_fw_version = device_before.get("fw_version")

            salt = await self.get_salt(ip)
            if not salt:
                raise ValidationError("Could not retrieve device salt")

            firmware_file = open(self.firmware_path, "rb")
            firmware_size = os.fstat(firmware_file.fileno()).st_size
            if firmware_size <= 0 or firmware_size > 0xFFFFFFFF:
                raise ValidationError("Firmware size is outside the API range")
            firmware_hash = hashlib.sha256()
            while True:
                chunk = firmware_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                firmware_hash.update(chunk)
            firmware_sha256 = firmware_hash.hexdigest()
            firmware_file.seek(0)

            ts = int(time.time())
            payload = {
                "cmd": "set.system.update_firmware",
                "ts": ts,
                "token": self.generate_token("set.system.update_firmware", salt, ts),
                "account": self.current_account
            }
            await self.api_semaphore.acquire()
            api_slot_acquired = True
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, API_PORT),
                timeout=CONNECTION_TIMEOUT
            )
            data = json.dumps(payload, ensure_ascii=True, separators=(',', ':')).encode('ascii')
            writer.write(len(data).to_bytes(4, 'little') + data)
            await writer.drain()
            length = int.from_bytes(
                await asyncio.wait_for(reader.readexactly(4), READ_TIMEOUT), 'little'
            )
            if length <= 0 or length > 1024 * 1024:
                raise CommandError(f"Invalid firmware response length: {length}")
            init_resp = json.loads(
                (await asyncio.wait_for(reader.readexactly(length), READ_TIMEOUT)).decode('ascii')
            )
            if (
                not isinstance(init_resp, dict)
                or init_resp.get("code") != 0
                or init_resp.get('msg') != "ready"
            ):
                raise ConnectionError("Устройство не готово к обновлению")

            logging.info(
                f"{ip}: Образ для передачи: {firmware_size} байт, SHA-256 {firmware_sha256}"
            )

            writer.write(firmware_size.to_bytes(4, 'little'))
            await writer.drain()

            # Отправка данных прошивки
            sent = 0
            while sent < firmware_size:
                chunk_size = min(CHUNK_SIZE, firmware_size - sent)
                chunk = firmware_file.read(chunk_size)
                if len(chunk) != chunk_size:
                    raise CommandError("Firmware file changed during upload")
                writer.write(chunk)
                await writer.drain()
                sent += chunk_size
                progress = sent / firmware_size
                self.operation_progress[ip] = ("update", time.time(), UPDATE_DURATION, f"upload {progress:.1%}")
            firmware_file.close()
            firmware_file = None

            response_prefix = await asyncio.wait_for(reader.readexactly(2), READ_TIMEOUT)
            if response_prefix.lower() == b"ok":
                completion_resp = {"code": 0, "msg": "ok"}
            else:
                length_bytes = response_prefix + await asyncio.wait_for(
                    reader.readexactly(2), READ_TIMEOUT
                )
                length = int.from_bytes(length_bytes, 'little')
                if length <= 0 or length > 1024 * 1024:
                    raise CommandError(
                        f"Invalid firmware completion response length: {length}"
                    )
                response_data = await asyncio.wait_for(
                    reader.readexactly(length), READ_TIMEOUT
                )
                try:
                    completion_resp = json.loads(response_data.decode('ascii'))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    if response_data.strip().lower() in {b"ok", b"success"}:
                        completion_resp = {"code": 0, "msg": "ok"}
                    else:
                        raise CommandError("Invalid firmware completion response")

            if not isinstance(completion_resp, dict):
                raise CommandError("Invalid firmware completion response")
            completion_code = completion_resp.get('code')
            completion_msg = completion_resp.get('msg')
            successful_codes = (0, "0")
            successful_messages = {"ok", "success"}
            if (
                completion_code not in successful_codes
                and str(completion_msg).strip().lower() not in successful_messages
            ):
                raise CommandError(
                    "Устройство отклонило прошивку: "
                    f"code={completion_code}, msg={completion_msg}"
                )

            logging.info(f"{ip}: API завершил прием файла; ожидаются проверка пакета и перезагрузка")
            writer.close()
            await writer.wait_closed()
            writer = None
            self.api_semaphore.release()
            api_slot_acquired = False
            self.operation_progress[ip] = ("update", time.time(), UPDATE_DURATION, "finalizing")
            await asyncio.sleep(UPDATE_DURATION)

            device_after = await self.get_device_data(ip)
            if not device_after.get("online"):
                logging.warning(f"{ip}: Устройство недоступно после передачи; обновление не подтверждено")
            elif previous_fw_version and device_after.get("fw_version") != previous_fw_version:
                logging.info(
                    f"{ip}: Прошивка обновлена: {previous_fw_version} -> {device_after.get('fw_version')}"
                )
            elif previous_fw_version:
                logging.warning(
                    f"{ip}: Версия прошивки не изменилась ({previous_fw_version}); обновление не подтверждено"
                )
            else:
                logging.warning(f"{ip}: Не удалось проверить версию прошивки после передачи")
        
        except Exception as e:
            logging.error(f"{ip}: Ошибка обновления: {str(e)}", exc_info=True)
            self.operation_progress.pop(ip, None)
        finally:
            if firmware_file:
                firmware_file.close()
            if writer and not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            if api_slot_acquired:
                self.api_semaphore.release()
            self.operation_progress.pop(ip, None)
            if self.monitor_running:
                await self.force_refresh_device(ip, delay=0)

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
            elif key == -1:
                await asyncio.sleep(MONITOR_INTERVAL)

    async def set_fan_mode(self, mode: str) -> bool:
        if mode not in {"normal", "zero"}:
            raise ValidationError(f"Unsupported fan mode: {mode}")
        if not self.selected_devices:
            return False

        success_count = 0
        for ip in self.selected_devices:
            response = await self.send_command(ip, {
                "cmd": "set.fan.zero_speed",
                "param": 1 if mode == "zero" else 0
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Режим вентиляторов изменен на {mode}")
                success_count += 1
            else:
                logging.error(f"{ip}: Ошибка изменения режима вентиляторов")
        return success_count == len(self.selected_devices)

    async def set_led_mode(self) -> bool:
        if not self.selected_devices:
            return False

        success_count = 0
        for ip in self.selected_devices:
            response = await self.send_command(ip, {
                "cmd": "set.system.led",
                "param": [{
                    "color": "green",
                    "period": 1000,
                    "duration": 500,
                    "start": 0
                }]
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Настройки LED изменены")
                success_count += 1
            else:
                logging.error(f"{ip}: Ошибка изменения LED")
        return success_count == len(self.selected_devices)

    async def send_command(self, ip: str, command: Dict, retries: int = COMMAND_RETRIES) -> Dict:
        command_name = command.get("cmd")
        if not isinstance(command_name, str):
            return {"code": -3, "msg": "Command name is missing"}
        if retries < 1:
            return {"code": -1, "msg": "Retry count must be positive"}

        is_write = command_name.startswith("set.")
        if is_write and not ACCOUNTS.get(self.current_account):
            return {
                "code": -4,
                "msg": (
                    f"Password for account {self.current_account!r} "
                    "is not configured"
                ),
            }

        for attempt in range(retries):
            writer = None
            api_slot_acquired = False
            try:
                payload = dict(command)
                if is_write:
                    salt = await self.get_salt(ip)
                    if not salt:
                        return {
                            "code": -1,
                            "msg": "Could not retrieve device salt",
                        }
                    ts = int(time.time())
                    payload.update({
                        "ts": ts,
                        "token": self.generate_token(command_name, salt, ts),
                        "account": self.current_account
                    })
                    if (
                        command_name in ENCRYPTED_COMMANDS
                        and not isinstance(payload.get("param"), str)
                    ):
                        payload["param"] = self.encrypt_param(
                            payload["param"], command_name, salt, ts
                        )

                data = json.dumps(
                    payload, ensure_ascii=True, separators=(",", ":")
                ).encode("ascii")
                if len(data) > 1024 * 1024:
                    raise CommandError("Command payload is too large")

                await self.api_semaphore.acquire()
                api_slot_acquired = True
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, API_PORT),
                    timeout=CONNECTION_TIMEOUT
                )
                writer.write(len(data).to_bytes(4, 'little') + data)
                await writer.drain()

                length_bytes = await asyncio.wait_for(
                    reader.readexactly(4), READ_TIMEOUT
                )
                length = int.from_bytes(length_bytes, 'little')
                if length <= 0 or length > 1024 * 1024:
                    raise CommandError(f"Invalid response length: {length}")
                response_data = await asyncio.wait_for(
                    reader.readexactly(length), READ_TIMEOUT
                )
                response = json.loads(response_data.decode('utf-8'))
                if not isinstance(response, dict):
                    raise CommandError("API response must be a JSON object")
                if writer and not writer.is_closing():
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass
                    writer = None
                self.api_semaphore.release()
                api_slot_acquired = False
                return response
                
            except (
                asyncio.TimeoutError,
                asyncio.IncompleteReadError,
                OSError,
            ) as e:
                if is_write or attempt == retries - 1:
                    return {"code": -999, "msg": str(e) or "Connection failed"}
                await asyncio.sleep(1)
            except Exception as e:
                return {"code": -1, "msg": str(e)}
            finally:
                if writer and not writer.is_closing():
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass
                if api_slot_acquired:
                    self.api_semaphore.release()
        return {"code": -999, "msg": "Max retries exceeded"}

    async def get_salt(self, ip: str) -> str:
        if ip in self.salt_cache:
            return self.salt_cache[ip]
        
        response = await self.send_command(ip, {"cmd": "get.device.info", "param": "salt"})
        if response.get('code') == 0:
            message = response.get("msg")
            salt = (
                message.get("salt", "")
                if isinstance(message, dict)
                else message if isinstance(message, str) else ""
            )
            if salt:
                self.salt_cache[ip] = salt
                return salt
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
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False

    def validate_frequency(self, freq: int) -> bool:
        """Валидировать значение частоты"""
        return -100 <= freq <= 100

    def validate_power(self, power: int) -> bool:
        """Валидировать значение мощности"""
        return 0 <= power <= 99999

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
            elif key == -1:
                await asyncio.sleep(MONITOR_INTERVAL)

    async def _set_power_limit_dialog(self, stdscr):
        h, w = stdscr.getmaxyx()
        win = curses.newwin(5, 40, h//2-2, w//2-20)
        win.border()
        win.addstr(1, 2, "Лимит мощности (0-99999W):")
        win.refresh()
        
        try:
            power = int(self._get_input(win, 2, 2, 10))
            if self.validate_power(power):
                await self.set_power_limit(power)
            else:
                logging.error(
                    f"Некорректная мощность: {power}. "
                    "Допустимый диапазон: 0-99999W"
                )
        except (ValueError, ValidationError) as e:
            logging.error(f"Ошибка при установке лимита мощности: {str(e)}")

    async def _set_pools_dialog(self, stdscr):
        h, w = stdscr.getmaxyx()
        if h < 13 or w < 80:
            logging.error("Терминал слишком мал для настройки пулов")
            return
        win = curses.newwin(13, 80, h//2-6, max(0, w//2-40))
        win.border()
        win.addstr(1, 2, "Настройка пулов майнинга:")
        
        pools = []
        for i in range(3):
            row = 2 + i * 3
            win.addstr(row, 2, f"Pool {i+1} URL:")
            url = self._get_input(win, row, 14, 60)
            win.addstr(row + 1, 2, "Worker:")
            worker = self._get_input(win, row + 1, 14, 60)
            win.addstr(row + 2, 2, "Password:")
            password = self._get_input(win, row + 2, 14, 60, mask=True)
            pools.append({"pool": url, "worker": worker, "passwd": password})

        await self.set_pools(pools)

    async def _set_frequency_dialog(self, stdscr):
        """Диалог для установки частоты"""
        h, w = stdscr.getmaxyx()
        win = curses.newwin(5, 40, h//2-2, w//2-20)
        win.border()
        win.addstr(1, 2, "Частота (-100..100%):")
        win.refresh()
        
        try:
            freq = int(self._get_input(win, 2, 2, 10))
            if self.validate_frequency(freq):
                await self.set_frequency(freq)
            else:
                logging.error(
                    f"Некорректная частота: {freq}. "
                    "Допустимый диапазон: -100..100%"
                )
        except (ValueError, ValidationError) as e:
            logging.error(f"Ошибка при установке частоты: {str(e)}")

    async def set_pools(self, pools: List[Dict]) -> bool:
        if not self.selected_devices:
            return False
        if not isinstance(pools, list) or len(pools) > 3:
            raise ValidationError("One to three pool records are supported")
        if any(not isinstance(pool, dict) for pool in pools):
            raise ValidationError("Each pool must be an object")
        pools = [pool for pool in pools if pool.get("pool")]
        if not pools:
            return False

        success_count = 0
        for ip in self.selected_devices:
            response = await self.send_command(ip, {
                "cmd": "set.miner.pools",
                "param": pools
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Пулы успешно обновлены")
                success_count += 1
            else:
                logging.error(f"{ip}: Ошибка обновления пулов")
        return success_count == len(self.selected_devices)

    def _draw_menu(self, stdscr, title, items, y, x):
        h = len(items) + 4
        w = max(len(title)+2, max(len(i[1]) for i in items)+10)
        win = curses.newwin(h, w, y, x)
        win.border()
        win.addstr(1, 2, title, curses.A_BOLD)
        
        for i, (key, text, _) in enumerate(items):
            win.addstr(2+i, 2, f"[{key}] {text}")
        
        win.refresh()

    def _get_input(self, win, y, x, max_len, mask: bool = False):
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
            displayed_input = "*" * len(input_str) if mask else input_str
            win.addstr(y, x, displayed_input.ljust(max_len))
            win.refresh()
        return input_str.strip()

    async def set_power_mode(self, mode: str) -> bool:
        if mode not in {"normal", "low", "high"}:
            raise ValidationError(f"Unsupported power mode: {mode}")
        if not self.selected_devices:
            return False

        success_count = 0
        for ip in self.selected_devices:
            response = await self.send_command(ip, {
                "cmd": "set.miner.power_mode",
                "param": mode
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Режим питания изменен на {mode}")
                success_count += 1
            else:
                logging.error(f"{ip}: Ошибка изменения режима питания")
        return success_count == len(self.selected_devices)

    async def set_power_limit(self, power: int) -> bool:
        if not self.selected_devices:
            return False

        if not self.validate_power(power):
            logging.error(
                f"Неверное значение мощности {power}. "
                "Допустимый диапазон: 0-99999W"
            )
            raise ValidationError(f"Неверное значение мощности: {power}")

        success_count = 0
        for ip in self.selected_devices:
            response = await self.send_command(ip, {
                "cmd": "set.miner.power_limit",
                "param": power
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Лимит питания установлен на {power}W")
                success_count += 1
            else:
                logging.error(f"{ip}: Ошибка установки лимита питания")
        return success_count == len(self.selected_devices)

    async def factory_reset(self) -> bool:
        if not self.selected_devices:
            return False

        success_count = 0
        for ip in self.selected_devices:
            response = await self.send_command(ip, {
                "cmd": "set.system.factory_reset",
            })
            if response.get('code') == 0:
                logging.info(f"{ip}: Сброс к заводским настройкам выполнен")
                success_count += 1
            else:
                logging.error(f"{ip}: Ошибка сброса настроек")
        return success_count == len(self.selected_devices)

    async def set_frequency(self, frequency: int) -> bool:
        """Установить частоту майнинга (в процентах от базовой)"""
        if not self.selected_devices:
            return False

        if not self.validate_frequency(frequency):
            logging.error(
                f"Неверная частота {frequency}. "
                "Допустимый диапазон: -100..100%"
            )
            raise ValidationError(f"Неверная частота: {frequency}")

        success_count = 0
        for ip in self.selected_devices:
            try:
                response = await self.send_command(ip, {
                    "cmd": "set.miner.target_freq",
                    "param": frequency
                })
                if response.get('code') == 0:
                    logging.info(f"{ip}: Частота установлена на {frequency}%")
                    success_count += 1
                else:
                    logging.error(f"{ip}: Ошибка установки частоты: {response.get('msg')}")
            except Exception as e:
                logging.error(f"{ip}: Ошибка установки частоты: {str(e)}")

        return success_count == len(self.selected_devices)

async def scan_network(network: str) -> List[str]:
    try:
        parsed_network = ipaddress.ip_network(network, strict=False)
        if not isinstance(parsed_network, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 network ranges are supported")
    except ValueError as exc:
        raise ValidationError(
            f"Invalid IPv4 network range: {network}"
        ) from exc
    if parsed_network.num_addresses > MAX_SCAN_ADDRESSES:
        raise ValidationError(
            f"Network is too large; maximum is {MAX_SCAN_ADDRESSES} addresses"
        )

    nm = nmap.PortScanner()
    print(f"Scanning {parsed_network}...")
    await asyncio.to_thread(
        nm.scan, str(parsed_network), arguments=f"-p {API_PORT} --open"
    )
    devices = []
    for host in nm.all_hosts():
        try:
            ports = nm[host].get("tcp", {})
            if ports.get(API_PORT, {}).get("state") == "open":
                devices.append(str(ipaddress.IPv4Address(host)))
        except (KeyError, TypeError, ValueError):
            logging.warning("Ignoring invalid scan result host: %r", host)

    devices = sorted(set(devices), key=ipaddress.IPv4Address)
    temporary_config = f"{CONFIG_FILE}.tmp"
    with open(temporary_config, "w", encoding="utf-8") as f:
        json.dump(devices, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary_config, CONFIG_FILE)
    print(f"Devices found: {len(devices)}")
    return devices

def load_devices() -> List[str]:
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                configured_devices = json.load(f)
            if not isinstance(configured_devices, list):
                raise ValueError("Device configuration must be a JSON array")

            devices = set()
            for value in configured_devices:
                if not isinstance(value, str):
                    logging.warning(
                        "Ignoring non-string device address: %r", value
                    )
                    continue
                try:
                    devices.add(str(ipaddress.IPv4Address(value)))
                except ipaddress.AddressValueError:
                    logging.warning(
                        "Ignoring invalid IPv4 device address: %r", value
                    )
            return sorted(devices, key=ipaddress.IPv4Address)
        return []
    except Exception as e:
        logging.error(f"Failed to load devices: {str(e)}")
        return []

def main():
    configure_logging()
    parser = argparse.ArgumentParser(description="ASIC device monitoring")
    parser.add_argument("--scan", help="Network range to scan")
    parser.add_argument("--firmware", default=DEFAULT_FIRMWARE, help="Path to firmware file")
    parser.add_argument("--telegram", action="store_true", help="Start Telegram bot instead of curses UI")
    args = parser.parse_args()

    if not args.scan and not os.path.exists(CONFIG_FILE):
        print("Необходимо указать --scan для первого запуска")
        return

    devices = asyncio.run(scan_network(args.scan)) if args.scan else load_devices()
    monitor = DeviceMonitor(devices)
    monitor.firmware_path = args.firmware

    if args.telegram:
        from telegram_bot import run_telegram_bot
        run_telegram_bot(monitor)
        return

    def curses_main(stdscr):
        try:
            asyncio.run(monitor.monitor(stdscr))
        except KeyboardInterrupt:
            logging.info("Завершено пользователем")

    curses.wrapper(curses_main)

if __name__ == "__main__":
    main()
