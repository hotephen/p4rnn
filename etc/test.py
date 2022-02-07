import sys
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import hexdump, BitField, BitFieldLenField, ShortEnumField, X3BytesField, ByteField, XByteField



def main():
    f = open("weight_bnn.txt", 'r')
    lines = f.readlines()
    
    print(type(lines[0]))
    
    binary_1 = int(lines[0],2)

    print(type(binary_1))
    
    # lines = [line.rstrip('\n') for line in lines]
    
    # print(lines[0])

    test = "1000"
    test = int(test, 2)
    print(test)



if __name__ == '__main__':
    main()