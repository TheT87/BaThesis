from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


def geolocation(src_ip):
    dst = "172.17.144.87"
    sport = 40000
    dport = 40001
    # SYN
    ip = IP(src=src_ip, dst=dst)
    SYN = TCP(sport=sport, dport=dport, flags='S', seq=1000)
    SYNACK = sr1(ip / SYN)

    # ACK
    ACK = TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    send(ip / ACK)


def send_packet(ip_address):
    source_server = ip_address
    target_server = "172.17.144.87"

    # Send 10  packets
    for x in range(0, 15):
        port = random.randint(40000, 42000)
        layer_2 = Ether()
        layer_3 = IP(src=source_server, dst=target_server)
        layer_4 = TCP(sport=port,dport=port)
        tcp_pkt = layer_2 / layer_3 / layer_4
        sendp(tcp_pkt)


# Attack the target ip

if __name__ == '__main__':
    cn_src = "61.135.0.1"
    us_src = "69.162.81.55"
    de_src = "102.128.165.43"
    ru_src = "103.136.43.65"
    src_list = [cn_src, us_src, de_src, ru_src]
    for i in src_list:
        send_packet(i)
