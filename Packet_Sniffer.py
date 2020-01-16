#!/usr/bin/env python

import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface = interface, store = False, prn =process_sniffed_packet, filter = "")  # Here sniff is the function in the scapy which accepts a lots of arguments but here we are just giving the interface to this function
# here we passed the another argument which is the store here we pass the value of the store as the false which means donot store the collected data because it will put the stress on our memory
# this argument prn helps us to specify the callback function now what does callback function means a function which is called automatically whenever this function catches the new packet
# so for the each packet capture it will call the another function specify in the prn

# so basically here i am saying that for each packet capture call the function process_sniffed_packet()

# here we are passing the argument filter basically it will filters the packets that is being read by scapy.sniff function but intially it will give us a useless and all data so thats why we need to use the filter in this
# here filter can be of anytypes like
# if we are looking for the data like videos send, images or phone call placed basically which is uses the udp so we will write filter = "udp"
# if we are in seach for the ftp password now we should know that these passwords uses the port 21 so we will write filter = "port 21"
#     we looking for the data is send to web servers then we will use the port 80 because they will run on the port 80 by default

# now there is a lot of ways to add the filters go there for more info    https://biot.com/capstats/bpf.html
# now this filter doesnot work for the packets they has been send or recived through the http so in order to fix this we have to add the third party module in the python which is scapy_http we can install it by the command (pip install scapy_http)





def process_sniffed_packet(packet):                # here in the argument we will accept the packet which is searched by the scapy.sniff111
    print(packet)

sniff("eth0")

# now here what is happening lets see
# here first of all we have passed the interface eth0 if you are on the other interface like lan0 you can use that interface but here i am passing the
# interface eth0 as a argument to sniff
# now further in this function we are calling the other function which is made by scapy that function will do the hardwork for us to sniffed the data following
#     through the interface passed in the iface
# here we are also telling that donot store anything in the memory
# then we are telling the function that for each piece of data you sniff call the another function called process_sniffed_packet()
