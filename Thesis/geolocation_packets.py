from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


def attack(ip_address):
    source_server = ip_address
    target_server = "172.17.144.87"
    # Log target
    print("Performing attack on ip: {0}".format(target_server))

    # Send 10 attack packets
    for x in range(0, 15):
        port = random.randint(40000, 42000)
        l2 = Ether()
        l3 = IP(src=source_server, dst=target_server)
        l4 = TCP(sport=port, dport=port)
        tcp_pkt = l2 / l3 / l4
        sendp(tcp_pkt)


# Attack the target ip
if __name__ == '__main__':
    cn_src = "61.135.0.1"
    us_src = "69.162.81.55"
    de_src = "102.128.165.43"
    ru_src = "103.136.43.65"
    src_list = [cn_src, us_src, de_src, ru_src]
    for i in src_list:
        attack(i)