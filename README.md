# Spam-Pi (Integrated)

A unified wireless attack and reconnaissance suite for the Raspberry Pi. Perform BLE proximity spamming, WiFi beacon flooding, deauthentication attacks, and reconnaissance from a single multi-threaded tool.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

### 📡 Bluetooth Low Energy (BLE) Spam
- **Apple Proximity**: Trigger pairing prompts for AirPods, AirPods Pro, AirPods Max, and AppleTV.
- **Apple "Find My" / AirTag**: Broadcast "Offline Finding" signals for AirTags and iPhones.
- **Android Fast Pair**: Trigger "New device found" notifications on nearby Android devices.
- **Samsung Quick Pair**: Trigger pairing prompts for Samsung Galaxy Buds and devices.
- **Windows Swift Pair**: Trigger Microsoft Swift Pair notifications on Windows 10/11 PCs.
- **Cycle Mode**: Automatically rotate through all available BLE payloads for maximum visibility.
- **BLE Sniffer**: Scan and identify nearby Bluetooth devices with signal strength (RSSI).

### 📶 WiFi Attacks & Reconnaissance
- **Beacon Flooding**: Broadcast thousands of fake Access Points (SSIDs) to clutter WiFi lists.
- **Beacon "Karma" Attack**: Passively sniff for WiFi probe requests from nearby phones and automatically broadcast the exact SSIDs they are searching for.
- **Deauthentication Attack**: Kick specific devices off their network or target entire Access Points.
- **Authentication Flooding**: Overwhelm a router's client table with thousands of fake authentication requests to freeze or reboot the AP.
- **Handshake Snatching**: Automatically capture EAPOL 4-way handshakes during deauth attacks for offline cracking.
- **Probe Request Sniffing**: Listen for and log the network names that nearby smartphones and laptops have saved in their history.
- **Channel Hopping**: Automatically cycle through WiFi channels 1–13 to capture 100% of local wireless traffic.

### 🛠️ Advanced Tools & Automation
- **Multi-threaded Engine**: Run multiple BLE and WiFi attacks/sniffers in parallel without performance loss.
- **Hardware Autodetection**: Automatically identifies Bluetooth and WiFi adapters with manufacturer names.
- **Automated Logging**: 
  - Saves captured handshakes to `logs/handshakes.pcap`.
  - Logs discovered client probe requests to `logs/probes.log`.
- **Auto-Cleanup**: Gracefully stops all attacks and restores WiFi adapters from monitor mode to managed mode on exit.
- **MouseJack / NRF Spam**: Integrated framework for peripheral hijacking (requires NRF24L01 hardware).

## 📦 Installation

```bash
sudo apt update
sudo apt install python3-scapy bluez iw aircrack-ng
git clone https://github.com/gabhain/Spam-Pi
cd Spam-Pi
```

## 🖥️ Usage

```bash
sudo python3 spam_pi.py
```

## 🔗 References & Credits
- **[AppleJuice](https://github.com/ECTO-1A/AppleJuice)** - Apple BLE Proximity research.
- **[SourApple](https://github.com/ajay0/SourApple)** - ESP32 BLE spam implementation.
- **[WiFi Deauther](https://github.com/SpacehuhnTech/esp8266_deauther)** - WiFi beacon flooding research.
- **[Scapy](https://scapy.net/)** - Packet crafting and injection engine.

## ⚖️ License
MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer
Educational purposes only. Use only on hardware you own. Constant wireless flooding can disrupt communications and may be illegal in certain jurisdictions. Use responsibly.
