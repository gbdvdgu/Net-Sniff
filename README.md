# Network Packet Sniffer

This is a network packet sniffer built using Python and the `scapy` library. It captures and analyzes various types of network packets, providing alerts for specific port activity. It supports TCP, UDP, ICMP, and DNS packet sniffing, and alerts when packet counts exceed a user-defined limit.

## Features

- **Packet sniffing**: Capture TCP, UDP, ICMP, and DNS packets.
- **Port alerts**: Alert when traffic on common ports exceeds a threshold.
- **Packet details**: Extract and display detailed packet information, including IP addresses, ports, and protocol information.
- **Customizable**: Users can change the network interface, set alert limits, and choose the number of packets to sniff.
- **Packet count display**: View packet counts for each protocol.
- **Interactive menu**: Provides a user-friendly interface for setting options.

## Dependencies

- `scapy`: For packet sniffing and manipulation.
- `colorama`: For color-coded terminal output.

## Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/gbdvdgu/Net-Sniff
cd Net-Sniff
pip install -r requirements.txt
```

## Usage

1. Run the script:

   ```bash
   python Net-Sniff.py
   ```

2. Follow the on-screen menu to start sniffing packets, set alerts, or adjust configurations.

## Menu Options

- **0. Normal Sniff**: Capture and display packet information.
- **1. Alert Sniff**: Capture packets and alert if the count exceeds the defined limit.
- **2. Alert packet count**: View the packet count for each protocol.
- **3. Packet Alert Limit**: Set the maximum number of packets allowed before triggering an alert.
- **4. Change Interface**: Switch the network interface for sniffing.
- **5. Exit**: Exit the application.

## Example

```bash
python Net-Sniff.py
```

The packet sniffer will start capturing packets on the specified network interface. If the packet count exceeds the set limit for certain protocols (e.g., FTP, SSH, ICMP), it will trigger an alert.

## Default Ports Monitored

- FTP (21)
- SSH (22)
- Telnet (23)
- SNMP (161, 162)
- RIP (520)
- SMTP (25)
- DNS (53)

## Customization

- The default packet limit for alerts is 20, but it can be changed from the menu.
- The default interface is set to `MediaTek Wi-Fi 6 MT7921 Wireless LAN Card`, but this can be customized in the menu as well.

---
