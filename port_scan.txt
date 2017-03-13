 #! /user/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys


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

#put the ports into an array
ports = range(int(min_port), int(max_port)+1)
# 0x12 comes back in the packet info.
SYNACK = 0x12
# 0x14 is sent to the target port to indicate an RST termination of connection
RSTACK = 0x14

# ensure that target IP is up and responsive before starting to scan
def checkhost(ip_addr):
    try:
        ping = srl(IP(dst = ip_addr)/ICMP())
        return True
        print "/n[*] Target Host is up, starting scan..."
    except Exception:
        return False
        print "/n[!] Cannot determine if Host is up"

# perform the scan on each port
def portscan(port):
    srcport = RandShort()
    # send the packet to the port
    SYNACKpkt = srl(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S"))
    # determine if the returned packet is a SYNACK which demonstrates an open port
    pktflags = SYNACKpkt.getlayer(TCP).flags
    # evaluate the pktflags returned from the target port
    if pktflags == SYNACK: #if the SYNACK was successful, the port is open
        return True
    else:
        return False #otherwise it is not open (maybe filtered or closed)
    # send back an RST packet which will terminate the connection before it finishes
    # this makes it less likely the host machine will recognize a ocnnection was attempted
    RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
    send(RSTpkt) #this allows "stealth" scanning - its at least a little less noisy

# go through each target IP provided by the user
for var in target:
    host_test = checkhost(var) #check each target IP for all the ports
    if host_test == True:
        print "[*] Scanning Started !\n"
        # scan all the ports
        for port in ports:
            status = portscan(port)
            if status == True:
                print "Port " + str(port) + ": Open"
