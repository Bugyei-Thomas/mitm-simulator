# MITM Simulator

A man-in-the-middle attack simulator for authorized penetration testing and educational purposes. It performs ARP spoofing on a local network and integrates with mitmproxy for SSL stripping.

## Requirements

- Python 3
- scapy
- mitmproxy

## Installation

```bash
git clone https://github.com/s4wbvnny/mitm-simulator
cd mitm-simulator
pip3 install -r requirements.txt
```

## Usage

Requires root privileges:

```bash
sudo python3 mitm.py
```

1. Enter your network interface (e.g., `wlan0`, `eth0`).
2. Enter the network range to scan (e.g., `192.168.1.0/24`).
3. Select a device to impersonate as the default gateway.
4. Press `Ctrl+C` to stop and restore ARP tables.

## How It Works

1. Scans the local network using ARP requests to discover devices.
2. Presents a list of discovered devices for selection.
3. Performs ARP poisoning to redirect traffic through your machine.
4. Launches mitmproxy in transparent mode for SSL stripping.
5. Restores original ARP tables on exit.

## License

MIT
