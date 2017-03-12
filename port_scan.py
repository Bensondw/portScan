 #! /user/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime

target = []

try:
    # get the target IP addresses the user wants to scan
    mult_tar = raw_input("[*] Would you like to enter multiple targets? (y/n)")
    if mult_tar = "y":
        tar_quantity = raw_input("[*] How many targets would you like to enter?")
        try:
            for i in range(0, tar_quantity):
                    target.append(raw_input("[*] Enter Target IP Address: "))
    target.append(raw_input("[*] Enter Target IP Address: "))
    # find out which ports the user wants to scan on the targets
    min_port = raw_input("[*] Enter Minimum Port Number to scan on target(s): ")
    max_port = raw_input("[*] Maximum Port Number to scan on taget(s): ")


# make sure the port inputs are valid
    try:
        if int(min_port) >= 0 and int(max_port) >=0 and int(max_port) >= int(min_port):
            pass
        else:
            print: "\n[!] Invalid Range of Ports"
            print: "[!] Exiting"
            sys.exit(1)


ports = range(int(min_port), int(max_port)+1) #put the ports into an array
start_clock = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

# ensure that target IP is up and responsive before starting to scan
def checkhost(ip_addr):
    conf.verb = 0
    try:
        ping = srl(IP(dst = ip)/ICMP())
        print "/n[*] Target Host is up, beginning scan..."
    except Exception:
        print "/n[!] Couldn't resolve target"

# perform the scan on each port
def scanport(port):
    srcport = RandShort()
    conf.verb = 0
    SYNACKpkt = srl(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S"))
    pktflags = SYNACKpkt.getlayer(TCP).flags
    if pktflags == SYNACK:
        return True
    else:
        return False
    RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
    send(RSTpkt)

# go through each target IP provided by the user
for var in target:
    checkhost(var)
    print "[*] Scanning Started at " + strftime("%H:%M:%S") + "!\n"

    # scan all the ports
    for port in ports:
        status = scanport(port)
        if status == True:
            print "Port " + str(port) + ": Open"
