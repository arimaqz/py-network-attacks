import scapy.all as scapy

# syn, sync ack, rst -> rest connection

packet = scapy.IP(dst='192.168.104.91')/scapy.UDP(dport=137,sport=1234)
ans = scapy.sr1(packet,timeout=3,verbose=False)
if ans:
    print("[+] open")
else:
    print("[+] open|filtered")