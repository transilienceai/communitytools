#!/usr/bin/env python3
"""
Network Traffic Sniffer for CTF Flag Discovery
Captures packets and searches for 'CTF FLAG: XXX' pattern
No while loops, no try/except as per requirements
"""

from scapy.all import sniff, Raw
import re
import sys

def extract_flag(packet):
    """
    Extract flag from packet payload if present.
    Returns flag value (XXX part only) or None.
    """
    if packet.haslayer(Raw):
        payload = packet[Raw].load

        # Convert bytes to string, handle encoding errors
        if isinstance(payload, bytes):
            payload_str = payload.decode('utf-8', errors='ignore')
        else:
            payload_str = str(payload)

        # Search for flag pattern: 'CTF FLAG: XXX'
        match = re.search(r'CTF FLAG:\s*([A-Za-z0-9_\-]+)', payload_str, re.IGNORECASE)
        if match:
            flag_value = match.group(1)
            return flag_value

    return None

def packet_handler(packet):
    """
    Process each captured packet.
    If flag is found, print it and stop sniffing.
    """
    flag = extract_flag(packet)

    if flag:
        print(flag)
        sys.exit(0)

def main():
    """
    Main function to start packet sniffing.
    Sniffs all traffic on the interface and searches for the flag.
    """
    # Sniff packets - filter for packets with payload
    # Store=False to avoid memory issues with large captures
    # prn callback processes each packet
    # When flag is found, packet_handler calls sys.exit(0)
    sniff(
        filter="tcp or udp",
        prn=packet_handler,
        store=False
    )

if __name__ == "__main__":
    main()
