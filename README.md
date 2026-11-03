README.md
# ASIC Monitor

ASIC Monitor is a command-line interface (CLI) tool for monitoring and managing ASIC mining devices. It provides real-time statistics, device-level fault history, and detailed insights into individual devices. The interface is built using `curses` for an interactive terminal experience.

## Features

* **Real-time Monitoring**: Displays live status, hashrate, temperature, power consumption, and fan speeds of your ASIC devices.
* **Device Management**:
    * Reboot selected devices.
    * Control LED indicators.
    * Adjust power modes (normal, low, high).
    * Set power limits.
    * Configure mining pools.
    * Perform factory reset.
* **Interactive UI**: `curses`-based interface for easy navigation and selection.
* **Network Scanning**: Discover ASIC devices on your network.
* **Encrypted Communication**: Encrypts pool parameters and authenticates write commands according to the documented token flow.
* **Detailed Device View**: Toggle to see device information, pool status, and decoded device error codes.
* **Logging**: Logs all activities and errors to a file (`asic_monitor.log`).
* **Fault History**: Records fault and connectivity transitions with UTC date/time in `asic_faults.sqlite3`.
* **Fault Charts**: Prints per-device hourly or daily fault counts for a day, week, or month.

## Installation

1.  **Clone the repository**:
    ```bash
    git clone old06/whatsminer_m50-for-Linux
    cd whatsminer_m50-for-Linux
    ```

2.  **Create a virtual environment (recommended)**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Accounts and Telegram (optional)**:
    Create a `.env` file in the project root and add your ASIC device account passwords. By default, the script uses a "super" account and three "user" accounts.
    ```
    SUPER_PASSWORD="your_super_password"
    USER1_PASSWORD="your_user1_password"
    USER2_PASSWORD="your_user2_password"
    USER3_PASSWORD="your_user3_password"
    ```

    Ensure you replace `"your_super_password"` etc. with your actual passwords.
    To enable the Telegram interface, also add the bot token from
    [@BotFather](https://t.me/BotFather) and the numeric Telegram user IDs that
    may control the miners:
    ```
    TELEGRAM_BOT_TOKEN="123456:your_bot_token"
    TELEGRAM_ALLOWED_USER_IDS="123456789,987654321"
    ```
    Never publish the token. An allowlist is required; an empty allowlist
    prevents the bot from starting.

## Usage

1.  **First-time setup (scan your network)**:
    You need to scan your network to discover ASIC devices. Replace `192.168.1.0/24` with your network's CIDR range.
    ```bash
    python3 asic.py --scan 192.168.1.0/24
    ```
    This will save the discovered devices to `asic_devices.json`.

2.  **Start monitoring**:
    After the initial scan, you can simply run:
    ```bash
    python3 asic.py
    ```
    The monitor will load devices from `asic_devices.json`.

3.  **View fault charts**:
    ```bash
    python3 asic.py --fault-chart --period day
    python3 asic.py --fault-chart --device 192.168.1.101 --period week
    python3 asic.py --fault-chart --period month
    ```
    Without `--device`, a separate chart is printed for every configured miner. The first run records new events from that point onward; older faults are not reconstructed.

4.  **Start the Telegram bot**:
    ```bash
    python3 asic.py --telegram
    ```
    `/status` returns a nicely formatted list, sorts devices by hashrate, and shows total hashrate, power consumption, and average temperature.
    When a temperature threshold is exceeded, it includes an overheat warning.

    Example `/status` output:
    ```text
    Device Status
    Devices: 3 (ON: 2, OFF: 1)
    Hashrate: 93.5 TH/s | Power: 6.8 kW | Average temp: 72.3°C
    WARNING: temperature exceeded on devices: 192.168.1.102.
    1. <code>192.168.1.101</code> — <b>ON</b> | 50.0 TH/s | 69.0°C | 3.4 kW
    2. <code>192.168.1.102</code> — <b>ON</b> | 43.5 TH/s | 75.6°C | 3.4 kW ❗
    3. <code>192.168.1.103</code> — <b>OFF</b> | 0.0 TH/s | 0.0°C | 0.0 kW
    ```

    Commands without an IP list apply to all configured devices.
    Use `/help` in Telegram for syntax. If the bot does not respond, send `/whoami`, copy the numeric ID into `TELEGRAM_ALLOWED_USER_IDS`, and restart the bot.

## Key Bindings

| Key         | Action                           | Description                                     |
| :---------- | :------------------------------- | :---------------------------------------------- |
| `↑` / `↓`   | Navigate                         | Move selection up/down                          |
| `Space`     | Toggle Selection                 | Select/Deselect the current device              |
| `a`         | Select/Deselect All              | Toggle selection for all listed devices         |
| `r`         | Reboot Devices                   | Initiate a reboot for all selected devices      |
| `p`         | Pause Monitoring                 | Pause/Resume real-time data updates             |
| `l`         | Set LED Mode                     | Change LED indicator settings                   |
| `m`         | Power Mode Menu                  | Access menu for power modes (normal, low, high) |
| `L`         | Set Power Limit                  | Set a power consumption limit (0-99999 W)       |
| `P`         | Set Pools                        | Configure mining pool settings                  |
| `d`         | Toggle Detailed View             | Switch between list view and detailed view for selected device |
| `F`         | Factory Reset                    | Perform a factory reset on selected devices     |
| `q` / `Esc` | Quit                             | Exit the application                            |

Firmware updates, frequency changes, and fan control are intentionally not
available. Fan speed and target frequency remain visible as read-only telemetry.

## Technologies Used

* **Python 3**
* **`curses`**: For terminal UI.
* **`python-nmap`**: For network scanning.
* **`pycryptodome`**: For cryptographic operations (AES encryption, SHA256 hashing).
* **`python-dotenv`**: For loading environment variables.
