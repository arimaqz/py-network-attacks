import scapy.all as scapy

IP = '192.168.1.0/24'

print("[+] Sending APR packets..")
packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=IP)

answered, unanswered = scapy.srp(packet,timeout=2,verbose=False)

for i in range(len(answered)):
	print("[+]", answered[i][1][scapy.ARP].psrc, "is at", answered[i][1][scapy.ARP].hwsrc)
