import sys
import re
import socket
import random
import subprocess
import ipaddress
import os
from scapy.all import *


'''
Features Implemented:
1. Allow command-line switches to specify a host and port.
2. Present a simple response to the user.                               -40 points
3. Allow multiple ports to be specified                                 -10 points
        Single port         -p int
        Comma seperated     -p int,int,int
        Range               -p int-int
4. Use of more than one protocol
    TCP or UDP (to complement the one already provided)                 –10 points
    ICMP                                                                -5 points
5. Allow more than one host to be scanned
    Allowing different ways to specify hosts (CIDR Notation)            –5 points
    Reading a text file of host IPs                                     -5 points
    Comma seperated                                                     -2 points
'''
#Use the following syntax while executing:
#cd into folder
#python portscan.py -dst_ip 192.168.207.42 -p 88 -sT
#

#------------------------------Declare Variables------------------------------#
arguments = len(sys.argv) - 1 #Counts Arguments
dst_ip = []
dst_port = []
TCP = False
UDPb = False
Pingb = False

#------------------------------Declare Funcations------------------------------#
def TCP_scan(ip,port):
    #Executes a TCP Port scan for given IP address and Port
    try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, int(port)))
            if result == 0:
                print ("     Port {}: 	 Open".format(port))

            else:
                print ("     Port {}: 	 Closed|Filtered".format(port))
            sock.close()

    except KeyboardInterrupt:
        print ("     You pressed Ctrl+C")
        sys.exit()

    except socket.gaierror:
        print ('     Hostname could not be resolved. Exiting')
        sys.exit()

    except socket.error:
        print ("     Couldn't connect to server")
        sys.exit()


def UDP_scan(ip,port):
    #Executes a TCP Port scan for given IP address and Port

    port= int(port)
    ippkt = IP(dst=ip)
    udppkt = UDP(dport=port,sport=random.randint(49152,65536))

    p = ippkt/udppkt

    rsp = sr(p,verbose=False,timeout = 20)
    try:
        check = rsp[0][ICMP][0][1][ICMP]
        print("     Port {} is closed".format(port))
    except IndexError:
        print("     Port {} is open|filtered".format(port))

def readfile(filepath):
    dst_ip = []
    txtfile = open(filepath, 'r')
    dst_ip= txtfile.read().splitlines()
    txtfile.close()

    return dst_ip

def PING_scan(ip):
    #Ping given IP address
    try:
        response = subprocess.check_output(
            ['ping', '-n', '1', host],
            stderr=subprocess.STDOUT,  # get all output
            universal_newlines=True  # return string not bytes
            )


        if "Lost = 0" in response:
            print('     ' + ip + ' is up!')
        else:
            print('     ' + ip + ' is down!')

    except subprocess.CalledProcessError:
        response = None
        print('     ' + ip + ' is down!')
#------------------------------Begin Main------------------------------#
# Read commandline switches
position = 1
while (arguments >= position):
    #Destination IP for remote scan
    if sys.argv[position] == '-dst_ip':
        argstring= sys.argv[position+1]

        #Check if given in CIDR notation
        if argstring.find('/', 0, len(argstring)) != -1:
            for ip in ipaddress.IPv4Network(argstring):
                dst_ip.append(str(ip))

            #Remove Network Address
            del dst_ip[0]
            #Remove Broadcast Address
            dst_ip.pop()

        #Check if given an IP Range
        elif argstring.find('-', 0, len(argstring)) != -1:
            dst_ip= (argstring).split('-')
            beg_ip=int(dst_ip[0])
            end_port=int(dst_ip[1])
            dst_ip.clear()

            while (dst_ip<=end_port):
                dst_ip.append(str(beg_port))
                beg_port += 1

        elif argstring.find(',', 0, len(argstring)) != -1:
            dst_ip = (argstring).split(',')

        else:
            dst_ip.append(sys.argv[position+1])

    #check if TCP_scan
    if sys.argv[position] == '-sT':
        TCP=True

    #check if given file to read IPs
    if sys.argv[position] == '-f':
        argstring= sys.argv[position+1]
        dst_ip = readfile(argstring)

    #Ports for scan
    if sys.argv[position] == '-p':
        argstring= sys.argv[position+1]

        #Split ports if comma seperated
        if argstring.find(',', 0, len(argstring)) != -1:
            dst_port = (argstring).split(',')

        #Split ports if hyphen seperated
        elif  argstring.find('-', 0, len(argstring))!= -1:
            dst_port = (argstring).split('-')
            beg_port=int(dst_port[0])
            end_port=int(dst_port[1])
            dst_port.clear()

            while (beg_port<=end_port):
                dst_port.append(str(beg_port))
                beg_port += 1
        #Else Capture Single Specified Port
        else:
            dst_port.append(argstring)

    # Check for Ping Flags
    if sys.argv[position] == '-ping':
        Pingb = True

    # Check for UDP scan flag
    if sys.argv[position] == '-sU':
        UDPb=True
        TCP=False

    # Check for Scan TCP & UDPb flag
    if sys.argv[position] == '-sTU':
        UDPb=True
        TCP=True

    position += 1

# Itterate through hosts given
for host in dst_ip:

    print ("-" * 60)
    print ("Please wait, scanning remote host", host)
    print ("-" * 60)

    if Pingb:
        print('     *****Begin Ping*****')
        PING_scan(host)

    if TCP:
        print('     *****Begin TCP Scan*****')
        for port in dst_port:
            TCP_scan(host,port)

    if UDPb:
        print('     *****Begin UDP Scan*****')
        for port in dst_port:
            UDP_scan(host,port)

print ("x" * 60)
print ("End of Scan")
print ("x" * 60)
