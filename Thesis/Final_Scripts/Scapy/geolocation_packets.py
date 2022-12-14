from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

# not used just testing
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


def traffic(ip_address):
    source_server = ip_address
    target_server = "172.17.144.87"
    
    # Send 10 attack packets
    for x in range(0, 15):
        port = random.randint(40000, 42000)
        tcp_pkt = Ether() / IP(src=source_server, dst=target_server) / TCP(sport=port,dport=port)
        sendp(tcp_pkt)


if __name__ == '__main__':
    # different locations for testing
    cn_src = "61.135.0.1"
    us_src = "69.162.81.55"
    de_src = "102.128.165.43"
    ru_src = "103.136.43.65"
    src_list = [cn_src, us_src, de_src, ru_src]
    for i in src_list:
        traffic(i)
