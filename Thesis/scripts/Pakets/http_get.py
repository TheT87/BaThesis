from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP, TCP_client
from scapy.layers.l2 import Ether


def httpget():
    load_layer("http")
    req = HTTP() / HTTPRequest(
        Accept_Encoding=b'gzip, deflate',
        Cache_Control=b'no-cache',
        Connection=b'keep-alive',
        Host=b'www.secdev.org',
        Pragma=b'no-cache'
    )
    a = TCP_client.tcplink(HTTP, "www.secdev.org", 80)
    answer = a.sr1(req)
    a.close()

if __name__ == '__main__':
    httpget()
