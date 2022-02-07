#!/usr/bin/env python

import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers 
from scapy.all import Packet, IPOption
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
from scapy.all import IP, TCP, UDP, Raw, Ether, Padding
from time import sleep
import argparse


parser = argparse.ArgumentParser(description='send entry packet')
parser.add_argument('--i', required=False, type=str, default='veth2', help='i')
a = parser.parse_args()
global count
global wrong
global total
count = 0
wrong = 0
total = 0
tos_count = 0

def handle_pkt(pkt):
    global count
    global wrong
    global total
    global tos_count

    if(IP in pkt):
        if (pkt[IP].tos == 1):
            tos_count = tos_count + 1
            if(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "131.202.243.84"):
                count = count + 1
            elif(pkt[IP].src == "192.168.5.122" and pkt[IP].dst == "198.164.30.2"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.110" and pkt[IP].dst == "192.168.5.122"):
                count = count + 1
            elif(pkt[IP].src == "192.168.4.118" and pkt[IP].dst == "192.168.5.122"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.113" and pkt[IP].dst == "192.168.5.122"):
                count = count + 1
            elif(pkt[IP].src == "192.168.1.103" and pkt[IP].dst == "192.168.5.122"):
                count = count + 1
            elif(pkt[IP].src == "192.168.4.120" and pkt[IP].dst == "192.168.5.122"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.2.110"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.4.120"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.1.103"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.2.113"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.4.118"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.2.109"):
                count = count + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.2.105"):
                count = count + 1
            elif(pkt[IP].src == "192.168.1.105" and pkt[IP].dst == "192.168.5.122"):
                count = count + 1
            elif(pkt[IP].src == "147.32.84.180"):
                count = count + 1
            elif(pkt[IP].src == "147.32.84.170"):
                count = count + 1
            elif(pkt[IP].src == "147.32.84.160"):
                count = count + 1
            elif(pkt[IP].src == "147.32.84.150"):
                count = count + 1
            elif(pkt[IP].src == "147.32.84.140"):
                count = count + 1
            elif(pkt[IP].src == "147.32.84.130"):
                count = count + 1
            elif(pkt[IP].src == "10.0.2.15"):
                count = count + 1
            elif(pkt[IP].src == "192.168.106.141"):
                count = count + 1
            elif(pkt[IP].src == "192.168.106.131"):
                count = count + 1
            elif(pkt[IP].src == "172.16.253.130"):
                count = count + 1
            elif(pkt[IP].src == "172.16.253.131"):
                count = count + 1
            elif(pkt[IP].src == "172.16.253.129"):
                count = count + 1
            elif(pkt[IP].src == "172.16.253.240"):
                count = count + 1
            elif(pkt[IP].src == "74.78.117.238"):
                count = count + 1
            elif(pkt[IP].src == "158.65.110.24"):
                count = count + 1
            elif(pkt[IP].src == "192.168.3.35"):
                count = count + 1
            elif(pkt[IP].src == "192.168.3.25"):
                count = count + 1
            elif(pkt[IP].src == "192.168.3.65"):
                count = count + 1
            elif(pkt[IP].src == "172.29.0.116"):
                count = count + 1
            elif(pkt[IP].src == "172.29.0.109"):
                count = count + 1
            elif(pkt[IP].src == "172.16.253.132"):
                count = count + 1
            elif(pkt[IP].src == "192.168.248.165"):
                count = count + 1
            
        elif(pkt[IP].tos == 0):
            if(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "131.202.243.84"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.5.122" and pkt[IP].dst == "198.164.30.2"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.110" and pkt[IP].dst == "192.168.5.122"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.4.118" and pkt[IP].dst == "192.168.5.122"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.113" and pkt[IP].dst == "192.168.5.122"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.1.103" and pkt[IP].dst == "192.168.5.122"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.4.120" and pkt[IP].dst == "192.168.5.122"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.2.110"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.4.120"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.1.103"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.2.113"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.4.118"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.2.109"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.2.112" and pkt[IP].dst == "192.168.2.105"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.1.105" and pkt[IP].dst == "192.168.5.122"):
                wrong = wrong + 1
            elif(pkt[IP].src == "147.32.84.180"):
                wrong = wrong + 1
            elif(pkt[IP].src == "147.32.84.170"):
                wrong = wrong + 1
            elif(pkt[IP].src == "147.32.84.160"):
                wrong = wrong + 1
            elif(pkt[IP].src == "147.32.84.150"):
                wrong = wrong + 1
            elif(pkt[IP].src == "147.32.84.140"):
                wrong = wrong + 1
            elif(pkt[IP].src == "147.32.84.130"):
                wrong = wrong + 1
            elif(pkt[IP].src == "10.0.2.15"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.106.141"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.106.131"):
                wrong = wrong + 1
            elif(pkt[IP].src == "172.16.253.130"):
                wrong = wrong + 1
            elif(pkt[IP].src == "172.16.253.131"):
                wrong = wrong + 1
            elif(pkt[IP].src == "172.16.253.129"):
                wrong = wrong + 1
            elif(pkt[IP].src == "172.16.253.240"):
                wrong = wrong + 1
            elif(pkt[IP].src == "74.78.117.238"):
                wrong = wrong + 1
            elif(pkt[IP].src == "158.65.110.24"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.3.35"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.3.25"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.3.65"):
                wrong = wrong + 1
            elif(pkt[IP].src == "172.29.0.116"):
                wrong = wrong + 1
            elif(pkt[IP].src == "172.29.0.109"):
                wrong = wrong + 1
            elif(pkt[IP].src == "172.16.253.132"):
                wrong = wrong + 1
            elif(pkt[IP].src == "192.168.248.165"):
                wrong = wrong + 1
        
    total = count + wrong
    if(total != 0):
        recall = count/total
    else:
        recall = 0

    print("total : {}, tos_count : {}, right : {}, wrong : {}, recall rate : {}".format(total,tos_count,count,wrong,recall))
    # print("right : ", count) # true posiive
    # print("right : ", wrong) # false negative
    # print("recall rate : ", count/total) # true positive / (true positive + false negative)
    


def main():
    
    iface = a.i
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    



if __name__ == '__main__':
    main()


# sudo python receive.py -i veth6


