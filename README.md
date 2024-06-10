# Packet Sniffer Tool

A simple Python tool to capture and analyze network packets. The tool displays relevant information such as source and destination IP addresses, protocols, and payload data.

## Features

- Captures network packets
- Displays source and destination IP addresses
- Identifies and displays TCP/UDP protocols
- Shows payload data of the packets

## Requirements

- Python 3.x
- `scapy` library
- `npcap` library (for Windows users)

## Installation

1. **Clone the repository**:

    ```bash
    https://github.com/mp100802/PRODIGY_CS_05.git
    ```

2. **Install Python dependencies**:

    ```bash
    pip install scapy
    ```

3. **Install npcap** (for Windows users):

    Download and install npcap from [npcap website](https://nmap.org/npcap/). Ensure to check the option that allows npcap to be used in `WinPcap API-compatible Mode`.

## Usage

1. **Run the script with administrative privileges**:

    - **On Windows**: Open Visual Studio Code (VS Code) as an administrator.
      - Right-click on the VS Code icon and select `Run as administrator`.
    - **On Linux/MacOS**: Use `sudo` to run the script.

2. **Execute the script**:

    Open your terminal and run:

    ```bash
    python packet_sniffer.py
    ```

3. **Stop the script**:

    Press `Ctrl+C` in the terminal where the script is running to stop the packet sniffing.

## Example Output
Starting packet sniffing... Press Ctrl+C to stop.

New Packet: IP / TCP 192.168.1.100:12345 > 192.168.1.1:80 S
Source IP: 192.168.1.100
Destination IP: 192.168.1.1
Protocol: TCP
Source Port: 12345
Destination Port: 80
Payload: b'...'

