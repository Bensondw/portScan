 #! /user/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
# RandShort() is
dst_port = 80

# so i need to take a host as input
# or a range of hosts

# take a port as input
# take a range of ports as input

# traceroute tutorial is online

# 
