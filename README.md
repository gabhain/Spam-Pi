# Spam-Pi (Elite Edition)

The ultimate unified wireless attack and reconnaissance suite for the Raspberry Pi. Perform BLE proximity spamming, WiFi beacon flooding, deauthentication attacks, and reconnaissance from a single multi-threaded tool.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 💎 Elite Features

- **Proximity Spam (Full Suite)**: Spoof Apple (AirPods, AirTags, Find My), Android Fast Pair, Samsung Quick Pair, and Windows Swift Pair notifications.
- **Beacon "Karma" Attack**: Passively listens for WiFi probe requests from nearby devices and automatically begins broadcasting the SSIDs they are looking for.
- **WiFi Auth Flooder**: Floods target Access Points with authentication requests to fill client tables and freeze the router.
- **Channel Hopping Recon**: Automatically cycles through WiFi channels 1–13 to capture 100% of local traffic.
- **Handshake & Probe Logging**: Automatically saves captured EAPOL 4-way handshakes to `.pcap` files and logs all discovered probe requests to a text file for later analysis.
- **Unified multi-threaded core**: Runs multiple attacks and sniffers in parallel without performance loss.

## 🛠️ Prerequisites

- **Hardware**: 
  - Raspberry Pi (tested on Pi 4/5) or any Linux machine.
  - Bluetooth Adapter.
  - WiFi Adapter supporting **Monitor Mode** and **Packet Injection**.
- **Software**: 
  - `python3-scapy`, `bluez`, `iw`, `aircrack-ng`.

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

## ⚖️ License

MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

Educational purposes only. Use only on hardware you own. Constant wireless flooding can disrupt communications and may be illegal in certain jurisdictions. Use responsibly.
