 #! /user/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime

target = []

try:
    mult_tar = raw_input("[*] Would you like to enter multiple targets? (y/n)")
    if mult_tar = "y":
        tar_quantity = raw_input("[*] How many targets would you like to enter?")
        try:
            for i in range(0, tar_quantity):
                    target.append(raw_input("[*] Enter Target IP Address: "))
    target.append(raw_input("[*] Enter Target IP Address: "))
    min_port = raw_input("[*] Enter Minimum Port Number to scan on target(s): ")
    max_port = raw_input("[*] Maximum Port Number to scan on taget(s): ")



    try:
        if int(min_port) >= 0 and int(max_port) >=0 and int(max_port) >= int(min_port):
            pass
        else:
            print: "\n[!] Invalid Range of Ports"
            print: "[!] Exiting"
            sys.exit(1)

ports = range(int(min_port), int(max_port)+1)
start_clock = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

def checkhost(ip_addr):
    conf.verb = 0
    try:
        ping = srl(IP(dst = ip)/ICMP())
        print "/n[*] Target Host is up, beginning scan..."
    except Exception:
        print "/n[!] Couldn't resolve target"


# so i need to take a host as input
# or a range of hosts

# take a port as input
# take a range of ports as input

# traceroute tutorial is online

#
