#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import hexdump, BitField, BitFieldLenField, ShortEnumField, X3BytesField, ByteField, XByteField

parser = argparse.ArgumentParser()
parser.add_argument('--weight_file', required=False, type=str, default='weight/weight_bnn.txt')
args = parser.parse_args()


class Weightwriting(Packet):

    name = "Weightwriting"

    fields_desc = [
        BitField("index", 1, 32), # index: 0~119, only need 7
        BitField("weight", 0, 120) # weight: (in decimal, largest is) 2^120 -1 = 1.1329*10^36, only need 37
    ]

def main():

# read 120x120 bit weight line by line from txt
    f = open(args.weight_file, 'r')
    lines = f.readlines()
    lines = [line.rstrip('\n') for line in lines]
    w=[]

    print("sending on interface %s (Bmv2 port)" % ('veth0'))

# send one line (120 bits converted to decimal) for 120 times
    for i in range(0, 121):
        w.append(int(lines[i], 2))
        pkt = Ether() / IP(proto=61) / Weightwriting(index=i, weight=w[i])
        pkt.show()
        hexdump(pkt)
        sendp(pkt, iface='veth0', verbose=False)

if __name__ == '__main__':
    main()

#sudo python3 ./send_bnnweight.py --weight_file weight_180000.txt
