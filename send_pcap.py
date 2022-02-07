#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import hexdump
from kamene.all import *
# from scapy.all import rdpcap
# from scapy.all import *


def send_packet(pkt):
    pkt.show()
    sendp(pkt, iface='veth0')

def main():

    pkts = rdpcap("/home/p4net/output11_00000_19700101090000.pcap")
    # sniff(offline="/home/p4net/output11_00000_19700101090000.pcap", prn=send_packet)
    iface = "veth0"

    for i in range(1,len(pkts)): # 10~19 (11~20 in wireshark)
        pkts[i].show()
        try:
            sendp(pkts[i], iface=iface)
            print("packet {} sent.".format(i))
        except OSError:
            print("packet length: ", len(pkts[i]))
            


        

    

    
    # pkt =  Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:01', type=0x800)
    # pkt1 = pkt / IP(src=src_addr,dst=dst_addr) / TCP(dport=80, sport=20) / "hi"
    # pkt1.show()
    # hexdump(pkt1) # show hexadecimal expression of packet
    # sendp(pkt1, iface=iface, verbose=False)


if __name__ == '__main__':
    main()


# usage : python send.py src dst veth
