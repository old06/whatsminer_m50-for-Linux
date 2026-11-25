# Быстрый старт

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Создайте `.env` рядом с `asic.py`:

```dotenv
SUPER_PASSWORD="пароль_аккаунта_super"
USER1_PASSWORD="пароль_аккаунта_user1"
USER2_PASSWORD="пароль_аккаунта_user2"
USER3_PASSWORD="пароль_аккаунта_user3"
```

Для записи на устройствах задайте пароль и включите API write access согласно
настройкам WhatsMiner. Без пароля команды изменения параметров не отправляются.

## Запуск

Просканируйте свою IPv4-сеть, в которой разрешено администрировать устройства:

```bash
python3 asic.py --scan 192.168.1.0/24
```

Список устройств сохранится рядом с `asic.py`. Для мониторинга запустите:

```bash
python3 asic.py
```

Журнал неисправностей автоматически создаётся в `asic_faults.sqlite3` и
содержит время появления/исчезновения ошибок и потери связи.

Показать статистику за сутки, неделю или месяц:

```bash
python3 asic.py --fault-chart --period day
python3 asic.py --fault-chart --device 192.168.1.100 --period week
python3 asic.py --fault-chart --period month
```

Без `--device` график выводится отдельно для каждого настроенного устройства.

## Сервер и удалённый клиент

На сервере установите системный `nmap`, задайте отдельный токен для каждого
клиента и запустите сервер. Указывайте только приватную сеть, которой вы
управляете; сервер ограничивает её размер 4096 адресами.

```bash
export ASIC_CLIENT_TOKENS='{"laptop":"<64-hex-token>","ops":"<another-64-hex-token>"}'
python3 server.py --network 192.168.1.0/24 --host 0.0.0.0 --port 8080
```

Для фонового запуска используйте `systemd/asic-monitor.service`: настройте
пути и пользователя службы, укажите `ASIC_NETWORK`, `ASIC_CLIENT_TOKENS` и
пароли ASIC в `/etc/asic-monitor.env`, затем выполните:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now asic-monitor
```

Клиенту передайте его персональный токен как `ASIC_SERVER_TOKEN`. Помимо
прежней curses-консоли доступны история ошибок и операции управления:

```bash
export ASIC_SERVER_TOKEN="персональный_токен_клиента"
python3 asic.py --server http://miner-server:8080
```

Клавиши и экраны такие же, как при локальной работе. Для скриптов есть CLI:

```bash
python3 client.py --server http://miner-server:8080 status
python3 client.py --server http://miner-server:8080 faults --period day
python3 client.py --server http://miner-server:8080 fault-report --period week --output faults.csv
python3 client.py --server http://miner-server:8080 reboot 192.168.1.100
python3 client.py --server http://miner-server:8080 power-mode --mode low 192.168.1.100
python3 client.py --server http://miner-server:8080 power-limit --power 3000 192.168.1.100
python3 client.py --server http://miner-server:8080 pools --file pools.json 192.168.1.100
python3 client.py --server http://miner-server:8080 led 192.168.1.100
python3 client.py --server http://miner-server:8080 factory-reset --confirm FACTORY_RESET 192.168.1.100
```

Ошибки собираются монитором автоматически и хранятся в `asic_faults.sqlite3`.
Команды управления требуют явных IP обнаруженных устройств; factory reset
требует дополнительного подтверждения. Порт `8080` использует HTTP без TLS:
ограничьте его межсетевым экраном и для доступа извне используйте VPN или
HTTPS reverse proxy. Не публикуйте порт в интернет.

## Управление

| Клавиша | Действие |
| --- | --- |
| `Up` / `Down` | Выбор устройства |
| `Space` | Выбрать или снять выбор |
| `a` | Выбрать все устройства или снять выбор |
| `r` | Перезагрузить выбранные устройства |
| `l` | Настройки LED |
| `m` | Режим питания |
| `L` | Лимит мощности, 0-99999 W |
| `P` | Настройка пулов |
| `d` | Подробности выбранного устройства, включая коды ошибок |
| `g` | Открыть график неисправностей выбранного устройства |
| `F` | Сброс выбранных устройств после подтверждения |
| `q` / `Esc` | Выход |

В режиме графика клавиши `1`, `2`, `3` переключают сутки, неделю и месяц,
стрелки `Up` / `Down` меняют устройство, а `Left` / `Right` листают даты,
если история не помещается на экран. Нажмите `a` для общего графика всех
устройств и `s` для сохранения CSV-отчёта в `reports/`. Отчёт содержит дату и
время (UTC и местное), IP устройства, код, состояние и описание события.
Нажмите `g`, чтобы вернуться к мониторингу.

Критические ошибки отображаются на главном экране красным цветом и знаком `!`.
Расшифровка берется из `reason` ответа `get.device.info` или из встроенного
справочника кодов.

## Telegram

Добавьте в `.env` токен бота и список Telegram ID, которым разрешено управление:

```dotenv
TELEGRAM_BOT_TOKEN="токен"
TELEGRAM_ALLOWED_USER_IDS="123456789,987654321"
```

Запуск:

```bash
python3 asic.py --telegram
```

Поддерживаются команды `/status`, `/devices`, `/reboot`, `/power`, `/mode` и `/help`. Команды управления доступны только ID из allowlist;
если IP не указан, команда применяется ко всем настроенным устройствам.

## Совместимость с API

Команды и параметры сверяются с [официальной документацией WhatsMiner API](https://apidoc.whatsminer.com/).
Статистика запрашивается через `get.miner.status` с фильтром `summary+pools`,
коды ошибок читаются из `get.device.info → msg.error-code`. Прошивка, частота и
вентиляторы доступны только для чтения или отключены; обороты вентиляторов и
целевое значение частоты остаются в телеметрии.
