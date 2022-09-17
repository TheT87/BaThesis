#! /usr/bin/env python

from scapy.all import *

hostname = "1.1.1.1"
for i in range(1,10):
	pkt=IP(dst=hostname, ttl=1)
	reply = sr1(pkt, verbose=0)
	if reply is None:
		break
	elif reply.type == 3:
		print("Done!", reply.src)
		break
	else:
		print("%d Hops away" % i ,reply.src)
