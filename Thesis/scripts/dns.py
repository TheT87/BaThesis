from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


def traffic_without_lookup():
    source_server = "172.17.144.41"
    target_server = "172.17.144.55"
    sport = random.randint(12345, 54321)
    dport = random.randint(12345, 54321)
    layer_2 = Ether()
    layer_3 = IP(src=source_server, dst=target_server)
    layer_4 = TCP(sport=sport, dport=dport)
    tcp_pkt = layer_2 / layer_3 / layer_4
    sendp(tcp_pkt)


def allowed_dns_traffic():
    source_server = "172.17.144.41"
    target_server = "172.17.144.22"
    sport = random.randint(12345, 54321)
    dport = random.randint(12345, 54321)
    layer_2 = Ether()
    layer_3 = IP(src=source_server, dst=target_server)
    layer_4 = TCP(sport=sport, dport=dport)
    tcp_pkt = layer_2 / layer_3 / layer_4
    sendp(tcp_pkt)


if __name__ == '__main__':
    for i in range(0, 1):
        allowed_dns_traffic()
        traffic_without_lookup()