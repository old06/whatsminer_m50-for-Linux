README.md
# ASIC Monitor

ASIC Monitor is a command-line interface (CLI) tool designed to monitor and manage ASIC mining devices. It provides real-time statistics, allows for mass operations like rebooting and firmware updates, and offers detailed insights into individual devices. The interface is built using `curses` for an interactive terminal experience.

## Features

* **Real-time Monitoring**: Displays live status, hashrate, temperature, power consumption, and fan speeds of your ASIC devices.
* **Device Management**:
    * Reboot selected devices.
    * Update firmware on multiple devices.
    * Set zero-speed fan mode (air-cooled devices only).
    * Control LED indicators.
    * Adjust power modes (normal, economic, high performance).
    * Set power limits.
    * Configure mining pools.
    * Perform factory reset.
* **Interactive UI**: `curses`-based interface for easy navigation and selection.
* **Network Scanning**: Discover ASIC devices on your network.
* **Encrypted Communication**: Encrypts pool parameters and authenticates write commands according to the documented token flow.
* **Detailed Device View**: Toggle to see comprehensive information for a selected device, including pool details.
* **Operation Progress Bars**: Visual feedback for long-running tasks like firmware updates.
* **Logging**: Logs all activities and errors to a file (`asic_monitor.log`).

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

5.  **Place Firmware File (for updates)**:
    If you plan to use the firmware update feature, place your firmware `.bin` file in the same directory as `asic.py` or specify its path using the `--firmware` argument. The default firmware file name is `firmware.bin`.

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

3.  **Specify Firmware Path (optional)**:
    If your firmware file is not named `firmware.bin` or is in a different location:
    ```bash
    python3 asic.py --firmware /path/to/your/firmware_file.bin
    ```

4.  **Start the Telegram bot**:
    ```bash
    python3 asic.py --telegram
    ```
    The bot supports `/status`, `/devices`, `/reboot`, `/frequency`,
    `/power`, and `/fan`.
<<<<<<< HEAD
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

    Commands without IP list apply to all configured devices.
    Use `/help` in Telegram for syntax. If the bot does not respond, send `/whoami`, copy the numeric ID into `TELEGRAM_ALLOWED_USER_IDS`, and restart the bot. 
## Key Bindings

| Key         | Action                           | Description                                     |
| :---------- | :------------------------------- | :---------------------------------------------- |
| `↑` / `↓`   | Navigate                         | Move selection up/down                          |
| `Space`     | Toggle Selection                 | Select/Deselect the current device              |
| `A`         | Select/Deselect All              | Toggle selection for all listed devices         |
| `R`         | Reboot Devices                   | Initiate a reboot for all selected devices      |
| `U`         | Update Firmware                  | Initiate a firmware update for selected devices |
| `P`         | Pause Monitoring                 | Pause/Resume real-time data updates             |
| `F`         | Fan Control Menu                 | Access menu for fan speed settings              |
| `L`         | Set LED Mode                     | Change LED indicator settings                   |
| `M`         | Power Mode Menu                  | Access menu for power modes (normal, economic, high) |
| `L`         | Set Power Limit                  | Set a power consumption limit (0-99999 W)       |
| `P`         | Set Pools                        | Configure mining pool settings                  |
| `D`         | Toggle Detailed View             | Switch between list view and detailed view for selected device |
| `F`         | Factory Reset                    | Perform a factory reset on selected devices     |
| `Q` / `Esc` | Quit                             | Exit the application                            |

The tool intentionally does not expose voltage control, arbitrary log reading,
configuration backup/restore, USB inspection, thermal throttling, statistics
reset, or automatic recovery: these commands are not present in the current
official WhatsMiner API command list. Frequency control uses the documented
`set.miner.target_freq` range of `-100..100`; positive increases may be limited
on air-cooled devices.

## Technologies Used

* **Python 3**
* **`curses`**: For terminal UI.
* **`python-nmap`**: For network scanning.
* **`pycryptodome`**: For cryptographic operations (AES encryption, SHA256 hashing).
* **`python-dotenv`**: For loading environment variables.
