from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


# Send traffic on specific port without matching process running
def traffic_without_process():
    source_server = "172.17.144.87"
    target_server = "172.123.123." + str(random.randint(2, 255))
    sport = random.randint(12345, 54321)
    dport = random.randint(12345, 54321)
    layer_2 = Ether()
    layer_3 = IP(src=source_server, dst=target_server)
    layer_4 = TCP(sport=sport, dport=dport)
    tcp_pkt = layer_2 / layer_3 / layer_4
    sendp(tcp_pkt)


def traffic_on_forbidden_ports():
    target_server = "172.17.144.87"
    source_server = "172.123.123." + str(random.randint(2, 255))
    sport = random.randint(12345, 54321)
    dport = random.randint(12345, 54321)
    layer_2 = Ether()
    layer_3 = IP(src=source_server, dst=target_server)
    layer_4 = TCP(sport=sport, dport=dport)
    tcp_pkt = layer_2 / layer_3 / layer_4
    sendp(tcp_pkt)


if __name__ == '__main__':
    for i in range(0, 20):
        traffic_without_process()
        traffic_on_forbidden_ports()
