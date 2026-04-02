# Spam-Pi (Professional)

The ultimate unified wireless attack and reconnaissance suite for the Raspberry Pi.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🔥 Professional Features

- **Live TUI Dashboard**: Real-time interactive dashboard showing nearby Access Points, connected clients, BLE devices, and live probe requests.
- **Smart Target Selection**: Identify specific clients connected to an AP and launch targeted deauthentication attacks.
- **OUI Manufacturer Lookup**: Automatically identifies the manufacturer of nearby WiFi and Bluetooth devices (Apple, Samsung, Intel, etc.).
- **5GHz Support**: Expanded channel hopping support for both 2.4GHz and 5GHz bands (hardware dependent).
- **Handshake Verification**: Real-time detection and verification of WPA 4-way handshakes.
- **Beacon "Karma" Attack**: Passively mimicks the networks nearby devices are searching for.
- **Automated Logging**: Saves captured handshakes to `logs/handshakes.pcap` and client probes to `logs/probes.log`.

## 🛠️ Prerequisites

- **Hardware**: 
  - Raspberry Pi (tested on Pi 4/5).
  - WiFi Adapter supporting **Monitor Mode** and **Packet Injection**.
- **Software**: 
  - `sudo apt install python3-scapy python3-rich bluez iw aircrack-ng`

## 📦 Installation

```bash
git clone https://github.com/gabhain/Spam-Pi
cd Spam-Pi
sudo python3 spam_pi.py
```

## ⚖️ License
MIT License.

## ⚠️ Disclaimer
Educational purposes only. Use only on hardware you own.
