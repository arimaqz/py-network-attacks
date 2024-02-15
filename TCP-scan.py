import scapy.all as scapy

syn = scapy.IP(dst='192.168.1.91')/scapy.TCP(flags='S', dport=445,sport=1234)
ans = scapy.sr1(syn,timeout=3,verbose=False)
if ans:
    if ans[scapy.TCP].flags == "SA":
        print("[+] port is open")
        ack = scapy.IP(dst='192.168.1.91')/scapy.TCP(flags='A', dport=445,sport=1234)
        fin = scapy.IP(dst='192.168.1.91')/scapy.TCP(flags='F', dport=445,sport=1234)
        scapy.send(ack,verbose=False)
        scapy.send(fin,verbose=False)
    elif ans[scapy.TCP].flags == "R":
        print("[+] port is closed")
else:
    print("[-] port may be filtered")
    