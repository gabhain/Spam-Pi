# Spam-Pi (Integrated)

A unified tool for Raspberry Pi to perform both BLE proximity spamming and WiFi Beacon flooding simultaneously.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- **Unified Selection**: Choose your Bluetooth and WiFi adapters from a single list with manufacturer names.
- **Combined Modes**:
  - **BLE Only**: Cycles through all proximity payloads (Apple, Android, Samsung).
  - **WiFi Only**: Broadcasts common public SSIDs.
  - **BOTH**: Runs both BLE and WiFi spamming in parallel using multi-threading.
- **Customization**: Pick specific Apple, Android, or Samsung payloads, or create custom WiFi SSID lists.
- **Auto-Cleanup**: Automatically stops advertising and restores WiFi to "managed" mode on exit (Ctrl+C).
- **Multi-threaded**: Optimized for concurrent operations without performance loss.

## 🛠️ Prerequisites

- **Hardware**:
  - Raspberry Pi (tested on Pi 4/5) or any Linux machine.
  - Bluetooth Adapter (Internal or USB Dongle).
  - WiFi Adapter (Must support **Monitor Mode** and **Packet Injection**).
- **Permissions**: Root privileges required for raw HCI and WiFi packet injection.

## 📦 Installation

```bash
# Update system
sudo apt update

# Install dependencies
sudo apt install python3-scapy bluez iw aircrack-ng

# Clone the repository
git clone https://github.com/your-username/Spam-Pi
cd Spam-Pi
```

## 🖥️ Usage

Run the integrated script with sudo:

```bash
sudo python3 spam_pi.py
```

## 📝 How it works

- **BLE**: Uses `hcitool` to inject raw HCI packets into the Bluetooth controller, spoofing manufacturer data at high frequency to trigger proximity notifications on nearby devices.
- **WiFi**: Uses the `scapy` library to craft and inject raw 802.11 Beacon frames, making them appear as legitimate Access Points in the area.

## 🔗 References & Credits

This project was inspired by and built upon research from the following amazing open-source projects:

- **[AppleJuice](https://github.com/ECTO-1A/AppleJuice)** - The original research into Apple BLE Proximity pairing exploits.
- **[SourApple](https://github.com/ajay0/SourApple)** - ESP32 implementation of the Apple BLE spam.
- **[WiFi Deauther](https://github.com/SpacehuhnTech/esp8266_deauther)** - Inspiration for WiFi beacon flooding and network stress testing.
- **[Scapy](https://scapy.net/)** - The powerful Python library used for all WiFi packet crafting and injection.
- **[BlueZ](http://www.bluez.org/)** - The Linux Bluetooth stack providing the HCI tools used for BLE injection.

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and testing purposes only. Use responsibly and only on networks or equipment you own. Constant beacon flooding or Bluetooth spamming can disrupt communications and should not be used in public environments. Use at your own risk.
