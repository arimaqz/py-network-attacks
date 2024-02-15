from scapy.all import *

def find_in_options(name,l):
    for i in l:
        if(i[0] == name): return i[1]
    return ""

def callback(packet):
    if packet.haslayer(DHCP):
        dhcp = packet.getlayer(DHCP)
        message_type = find_in_options("message-type",dhcp.options)
        if(message_type == 2): # OFFER
            print("[DHCP OFFER]")
            name_server = find_in_options("name_server",dhcp.options)
            server_id = find_in_options("server_id",dhcp.options)
            router = find_in_options("router",dhcp.options)
            subnet_mask = find_in_options("subnet_mask",dhcp.options)
            broadcast_address = find_in_options("broadcast_address",dhcp.options)
            lease_time = find_in_options("lease_time",dhcp.options)
            print(f"\tname server: {name_server}")
            print(f"\tserver id: {server_id}")
            print(f"\trouter: {router}")
            print(f"\tsubnet mask: {subnet_mask}")
            print(f"\tbroadcast address: {broadcast_address}")
            print(f"\tlease time: {lease_time}")
    if packet.haslayer(TCP):
        tcp = packet.getlayer(TCP)
        print("[TCP]")
        print("\tsource port:",tcp.sport)
        print("\tdestination port:",tcp.dport)
    if packet.haslayer(UDP):
        udp = packet.getlayer(UDP)
        print("[UDP]")
        print("\tsource port:",udp.sport)
        print("\tdestination port:",udp.dport)
    if packet.haslayer(ARP):
        arp = packet.getlayer(ARP)
        if(arp.op == 2):
            print("[ARP REPLY]")
            print("\tIP:",arp.psrc)
            print("\tMAC:",arp.hwsrc)
    if packet.haslayer(DNS):
        dns = packet.getlayer(DNS)
        if(dns.an):
            print('[DNS ANSWER]')
            print("\tdomain name:",dns.an.rrname.decode())
            print("\tIP:",dns.an.rdata)
sniff(prn=callback)