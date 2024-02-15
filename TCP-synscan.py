import scapy.all as scapy


packet = scapy.IP(dst='192.168.1.91')/scapy.TCP(flags='S', dport=445,sport=1234)
ans = scapy.sr1(packet,timeout=3,verbose=False)
if ans:
    if ans[scapy.TCP].flags == "SA":
        print("[+] port is open")
        packet = scapy.IP(dst='192.168.1.91')/scapy.TCP(flags='R', dport=445,sport=1234)
        scapy.send(packet,verbose=False)
    elif ans[scapy.TCP].flags == "R":
        print("[-] port is closed")
else:
    print("[-] port may be filtered")

    