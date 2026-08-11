#!/usr/bin/env python3
"""Telegram interface for DeviceMonitor."""

import functools
import html
import logging
import os
import asyncio
from typing import Awaitable, Callable, List, Set, TypeVar

from telegram import Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
)

from asic import DeviceMonitor, DeviceError, ValidationError


T = TypeVar("T")
CommandCallback = Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[T]]


def _allowed_user_ids() -> Set[int]:
    raw_ids = os.getenv("TELEGRAM_ALLOWED_USER_IDS", "")
    try:
        return {int(value.strip()) for value in raw_ids.split(",") if value.strip()}
    except ValueError as exc:
        raise ValueError(
            "TELEGRAM_ALLOWED_USER_IDS должен содержать только числовые Telegram ID"
        ) from exc


def authorized(
    handler: CommandCallback[T],
) -> CommandCallback[T]:
    @functools.wraps(handler)
    async def wrapper(
        self: "TelegramBot",
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> T:
        user = update.effective_user
        allowed_ids = context.application.bot_data["allowed_user_ids"]
        if user is None or user.id not in allowed_ids:
            if update.effective_message:
                await update.effective_message.reply_text("Доступ запрещён.")
            logging.warning(
                "Отклонён запрос Telegram от user_id=%s",
                user.id if user else "unknown",
            )
            return None  # type: ignore[return-value]
        return await handler(self, update, context)

    return wrapper


def _selected_devices(monitor: DeviceMonitor, arguments: List[str]) -> Set[str]:
    devices = set(arguments) if arguments else set(monitor.devices)
    invalid = devices - set(monitor.devices)
    if invalid:
        raise ValueError(f"Неизвестные устройства: {', '.join(sorted(invalid))}")
    if not devices:
        raise ValueError("Список устройств пуст. Сначала выполните сканирование сети.")
    return devices


def _device_line(device: dict) -> str:
    status = "ON" if device.get("online") else "OFF"
    return (
        f"{html.escape(device['ip'])}: {status}, "
        f"{device.get('temp', 0):.1f}°C, "
        f"{device.get('hashrate', 0):.1f} TH/s, "
        f"{device.get('power', 0) / 1000:.1f} kW"
    )


def _help_text() -> str:
    return (
        "<b>Команды</b>\n"
        "/status [IP ...] — состояние устройств\n"
        "/reboot [IP ...] — перезагрузить устройства\n"
        "/frequency &lt;-100..100&gt; [IP ...] — установить частоту\n"
        "/power &lt;0..99999&gt; [IP ...] — установить лимит мощности\n"
        "/fan &lt;normal|zero&gt; [IP ...] — режим вентиляторов\n"
        "/help — эта справка\n\n"
        "Без списка IP команда применяется ко всем устройствам."
    )


class TelegramBot:
    def __init__(self, monitor: DeviceMonitor, allowed_user_ids: Set[int]):
        self.monitor = monitor
        self.allowed_user_ids = allowed_user_ids

    async def whoami(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        user = update.effective_user
        if update.effective_message and user:
            await update.effective_message.reply_text(
                f"Ваш Telegram user ID: {user.id}\n"
                "Добавьте это число в TELEGRAM_ALLOWED_USER_IDS."
            )

    @authorized
    async def help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.effective_message.reply_text(_help_text(), parse_mode="HTML")

    @authorized
    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            devices = _selected_devices(self.monitor, context.args)
            results = await self._get_devices(devices)
            text = "\n".join(_device_line(device) for device in results)
            await update.effective_message.reply_text(text or "Нет данных.")
        except ValueError as exc:
            await update.effective_message.reply_text(str(exc))

    @authorized
    async def reboot(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            self.monitor.selected_devices = _selected_devices(self.monitor, context.args)
            await self.monitor._init_async_resources()
            await self.monitor.reboot_devices()
            await update.effective_message.reply_text(
                f"Перезагрузка поставлена в очередь: {len(self.monitor.selected_devices)}."
            )
        except ValueError as exc:
            await update.effective_message.reply_text(str(exc))

    @authorized
    async def frequency(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._run_numeric_command(
            update, context, "frequency", "частота", self.monitor.set_frequency
        )

    @authorized
    async def power(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._run_numeric_command(
            update, context, "power", "лимит мощности", self.monitor.set_power_limit
        )

    @authorized
    async def fan(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            if not context.args or context.args[0] not in {"normal", "zero"}:
                raise ValueError("Использование: /fan normal|zero [IP ...]")
            self.monitor.selected_devices = _selected_devices(self.monitor, context.args[1:])
            await self.monitor.set_fan_mode(context.args[0])
            await update.effective_message.reply_text("Режим вентиляторов изменён.")
        except (ValueError, DeviceError) as exc:
            await update.effective_message.reply_text(f"Ошибка: {exc}")

    async def _run_numeric_command(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
        command: str,
        name: str,
        operation: Callable[[int], Awaitable[bool]],
    ) -> None:
        try:
            if not context.args:
                raise ValueError(f"Использование: /{command} <значение> [IP ...]")
            value = int(context.args[0])
            self.monitor.selected_devices = _selected_devices(self.monitor, context.args[1:])
            await operation(value)
            await update.effective_message.reply_text(f"{name.capitalize()} установлен.")
        except (ValueError, ValidationError, DeviceError) as exc:
            await update.effective_message.reply_text(f"Ошибка: {exc}")

    async def _get_devices(self, devices: Set[str]) -> List[dict]:
        results = await asyncio.gather(
            *(self.monitor.get_device_data(ip) for ip in sorted(devices))
        )
        return list(results)


def build_application(monitor: DeviceMonitor) -> Application:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        raise ValueError("Не задан TELEGRAM_BOT_TOKEN")
    allowed_ids = _allowed_user_ids()
    if not allowed_ids:
        raise ValueError("Не задан TELEGRAM_ALLOWED_USER_IDS")

    bot = TelegramBot(monitor, allowed_ids)

    async def initialize(application: Application) -> None:
        application.bot_data["allowed_user_ids"] = allowed_ids
        await monitor._init_async_resources()
        bot_info = await application.bot.get_me()
        print(
            f"Telegram-бот @{bot_info.username or bot_info.id} запущен. "
            "Ожидание команд...",
            flush=True,
        )

    async def shutdown(application: Application) -> None:
        await monitor.cleanup()

    application = (
        ApplicationBuilder()
        .token(token)
        .post_init(initialize)
        .post_shutdown(shutdown)
        .build()
    )
    application.add_handler(CommandHandler("start", bot.help))
    application.add_handler(CommandHandler("help", bot.help))
    application.add_handler(CommandHandler("whoami", bot.whoami))
    application.add_handler(CommandHandler("status", bot.status))
    application.add_handler(CommandHandler("devices", bot.status))
    application.add_handler(CommandHandler("reboot", bot.reboot))
    application.add_handler(CommandHandler("frequency", bot.frequency))
    application.add_handler(CommandHandler("power", bot.power))
    application.add_handler(CommandHandler("fan", bot.fan))
    application.add_error_handler(_error_handler)
    return application


async def _error_handler(
    update: object, context: ContextTypes.DEFAULT_TYPE
) -> None:
    logging.error("Ошибка обработки Telegram update: %s", context.error, exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(
            "Внутренняя ошибка бота. Подробности записаны в asic_monitor.log."
        )


def run_telegram_bot(monitor: DeviceMonitor) -> None:
    """Run the bot until interrupted."""
    application = build_application(monitor)
    # Python 3.14 no longer creates a current event loop implicitly, while
    # python-telegram-bot's run_polling expects one during setup.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        application.run_polling()
    except Exception:
        logging.exception(
            "Не удалось запустить Telegram-бота. Проверьте токен и подключение к Telegram."
        )
        raise
