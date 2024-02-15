from scapy.all import *

packet = \
    Ether(dst="ff:ff:ff:ff:ff:ff",src="11:22:33:44:55:66")/ \
    IP(src="0.0.0.0",dst="255.255.255.255")/UDP(dport=67,sport=68)/ \
    BOOTP(chaddr='11:22:33:44:55:66')/ \
    DHCP(options=[('message-type','discover'),'end'])

sendp(packet)