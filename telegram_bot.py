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

from asic import DeviceMonitor, DeviceError, ValidationError, OVERHEAT_TEMP


T = TypeVar("T")
CommandCallback = Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[T]]


def _allowed_user_ids() -> Set[int]:
    raw_ids = os.getenv("TELEGRAM_ALLOWED_USER_IDS", "")
    try:
        return {int(value.strip()) for value in raw_ids.split(",") if value.strip()}
    except ValueError as exc:
        raise ValueError(
            "TELEGRAM_ALLOWED_USER_IDS must contain only numeric Telegram IDs"
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
                await update.effective_message.reply_text("Access denied.")
            logging.warning(
                "Telegram request denied for user_id=%s",
                user.id if user else "unknown",
            )
            return None  # type: ignore[return-value]
        return await handler(self, update, context)

    return wrapper


def _selected_devices(monitor: DeviceMonitor, arguments: List[str]) -> Set[str]:
    devices = set(arguments) if arguments else set(monitor.devices)
    invalid = devices - set(monitor.devices)
    if invalid:
        raise ValueError(f"Unknown devices: {', '.join(sorted(invalid))}")
    if not devices:
        raise ValueError("Device list is empty. Scan the network first.")
    return devices


def _status_summary(devices: List[dict]) -> str:
    online = [d for d in devices if d.get("online")]
    total_hashrate = sum(d.get("hashrate", 0) for d in online)
    total_power = sum(d.get("power", 0) for d in online)
    avg_temp = (
        sum(d.get("temp", 0) for d in online) / len(online)
        if online
        else 0
    )
    online_count = len(online)
    offline_count = len(devices) - online_count

    return (
<<<<<<< HEAD
        "<b>Device Status</b>\n"
        f"Devices: <b>{len(devices)}</b> (ON: <b>{online_count}</b>, OFF: <b>{offline_count}</b>)\n"
        f"Hashrate: <b>{total_hashrate:.1f}</b> TH/s | "
        f"Power: <b>{total_power / 1000:.1f}</b> kW | "
        f"Average temp: <b>{avg_temp:.1f}</b>°C\n"
=======
        "<b>Статус устройств</b>\n"
        f"Устройств: <b>{len(devices)}</b> (ON: <b>{online_count}</b>, OFF: <b>{offline_count}</b>)\n"
        f"Хэшрейт: <b>{total_hashrate:.1f}</b> TH/s | "
        f"Потребление: <b>{total_power / 1000:.1f}</b> kW | "
        f"Средняя темп.: <b>{avg_temp:.1f}</b>°C\n"
>>>>>>> 3f681e167910f0e5766de3beb69b190f4ec33a80
    )


def _device_line(device: dict, index: int) -> str:
    status = "ON" if device.get("online") else "OFF"
    temp = device.get("temp", 0)
    hashrate = device.get("hashrate", 0)
    power = device.get("power", 0) / 1000
    warning = " ❗" if temp > OVERHEAT_TEMP else ""
    return (
        f"{index}. <code>{html.escape(device['ip'])}</code> — "
        f"<b>{status}</b> | "
        f"{hashrate:.1f} TH/s | "
        f"{temp:.1f}°C | "
        f"{power:.1f} kW{warning}"
    )


def _help_text() -> str:
    return (
<<<<<<< HEAD
        "<b>Commands</b>\n"
        "/status [IP ...] — device status, sorted by hashrate\n"
        "/devices [IP ...] — alias for /status\n"
        "/reboot [IP ...] — reboot devices\n"
        "/frequency &lt;-100..100&gt; [IP ...] — set frequency\n"
        "/power &lt;0..99999&gt; [IP ...] — set power limit\n"
        "/fan &lt;normal|zero&gt; [IP ...] — set fan mode\n"
        "/help — this help\n\n"
        "Without IP list, command applies to all devices."
=======
        "<b>Команды</b>\n"
        "/status [IP ...] — состояние устройств, сортировка по хэшрейту\n"
        "/devices [IP ...] — alias для /status\n"
        "/reboot [IP ...] — перезагрузить устройства\n"
        "/frequency &lt;-100..100&gt; [IP ...] — установить частоту\n"
        "/power &lt;0..99999&gt; [IP ...] — установить лимит мощности\n"
        "/fan &lt;normal|zero&gt; [IP ...] — режим вентиляторов\n"
        "/help — эта справка\n\n"
        "Без списка IP команда применяется ко всем устройствам."
>>>>>>> 3f681e167910f0e5766de3beb69b190f4ec33a80
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
                f"Your Telegram user ID: {user.id}\n"
                "Add this number to TELEGRAM_ALLOWED_USER_IDS."
            )

    @authorized
    async def help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.effective_message.reply_text(_help_text(), parse_mode="HTML")

    @authorized
    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            devices = _selected_devices(self.monitor, context.args)
            results = await self._get_devices(devices)
            results = sorted(results, key=lambda d: d.get("hashrate", 0), reverse=True)
            if not results:
<<<<<<< HEAD
                await update.effective_message.reply_text("No data.")
=======
                await update.effective_message.reply_text("Нет данных.")
>>>>>>> 3f681e167910f0e5766de3beb69b190f4ec33a80
                return

            overheat_devices = [d for d in results if d.get("temp", 0) > OVERHEAT_TEMP]
            message = _status_summary(results)
            if overheat_devices:
                names = ", ".join(html.escape(d["ip"]) for d in overheat_devices)
                message += (
<<<<<<< HEAD
                    f"<b>WARNING:</b> temperature exceeded on devices: {names}.\n"
=======
                    f"<b>ВНИМАНИЕ:</b> превышение температуры на устройствах: {names}.\n"
>>>>>>> 3f681e167910f0e5766de3beb69b190f4ec33a80
                )
            message += "\n".join(
                _device_line(device, idx + 1)
                for idx, device in enumerate(results)
            )
            await update.effective_message.reply_text(
                message,
                parse_mode="HTML",
                disable_web_page_preview=True,
            )
        except ValueError as exc:
            await update.effective_message.reply_text(str(exc))

    @authorized
    async def reboot(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            self.monitor.selected_devices = _selected_devices(self.monitor, context.args)
            await self.monitor._init_async_resources()
            await self.monitor.reboot_devices()
            await update.effective_message.reply_text(
                f"Reboot queued for {len(self.monitor.selected_devices)} device(s)."
            )
        except ValueError as exc:
            await update.effective_message.reply_text(str(exc))

    @authorized
    async def frequency(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._run_numeric_command(
            update, context, "frequency", "frequency", self.monitor.set_frequency
        )

    @authorized
    async def power(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._run_numeric_command(
            update, context, "power", "power limit", self.monitor.set_power_limit
        )

    @authorized
    async def fan(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            if not context.args or context.args[0] not in {"normal", "zero"}:
                raise ValueError("Usage: /fan normal|zero [IP ...]")
            self.monitor.selected_devices = _selected_devices(self.monitor, context.args[1:])
            await self.monitor.set_fan_mode(context.args[0])
            await update.effective_message.reply_text("Fan mode changed.")
        except (ValueError, DeviceError) as exc:
            await update.effective_message.reply_text(f"Error: {exc}")

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
                raise ValueError(f"Usage: /{command} <value> [IP ...]")
            value = int(context.args[0])
            self.monitor.selected_devices = _selected_devices(self.monitor, context.args[1:])
            await operation(value)
            await update.effective_message.reply_text(f"{name.capitalize()} set.")
        except (ValueError, ValidationError, DeviceError) as exc:
            await update.effective_message.reply_text(f"Error: {exc}")

    async def _get_devices(self, devices: Set[str]) -> List[dict]:
        results = await asyncio.gather(
            *(self.monitor.get_device_data(ip) for ip in sorted(devices))
        )
        return list(results)


def build_application(monitor: DeviceMonitor) -> Application:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN is not set")
    allowed_ids = _allowed_user_ids()
    if not allowed_ids:
        raise ValueError("TELEGRAM_ALLOWED_USER_IDS is not set")

    bot = TelegramBot(monitor, allowed_ids)

    async def initialize(application: Application) -> None:
        application.bot_data["allowed_user_ids"] = allowed_ids
        await monitor._init_async_resources()
        bot_info = await application.bot.get_me()
        print(
            f"Telegram bot @{bot_info.username or bot_info.id} started. "
            "Waiting for commands...",
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
    logging.error("Telegram update handling error: %s", context.error, exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(
            "Internal bot error. Details are logged to asic_monitor.log."
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
            "Failed to start Telegram bot. Check token and Telegram connectivity."
        )
        raise
