# PortScanner
Port Scanner created for Assignment 3

# Description:
Create a port scanner to scan either a specified set of TCP or UDP ports
(or both) in a language of your choice. If you are unfamiliar with a
suitable programming language, Python with the Scapy language is
recommended.

# Features Implemented:
1. Allow command-line switches to specify a host and port.
2. Present a simple response to the user.                               -40 points
3. Allow multiple ports to be specified                                 -10 points
   ###### Single port
   ###### Comma separated
   ###### Range
4. Use of more than one protocol
   ###### TCP or UDP (to complement the one already provided)                 –10 points
   ###### ICMP                                                                -5 points
5. Allow more than one host to be scanned
   ###### Allowing different ways to specify hosts (CIDR Notation)            –5 points
   ###### Reading a text file of host IPs                                     -5 points
   ###### Comma separated                                                    -2 points

# Flags
    -dst_ip         Destination IP address for remote scan.
                    Supports:
                        single ip           -dst_ip x.x.x.x
                        CIDR notation       -dst_ip x.x.x.x/x

    -p              Port for scans
                    Supports:
                        single port         -p int
                        comman seperated    -p int,int,int
                        Range               -p int-int

    -sU             Scan UDP

    -sTU            Scan TCP and UDP

    -f              Read IPs from file
                    Supports:
                        line Separated IPs
    -ping           Ping specified host

# Examples of Common Tasks:
## TCP Scan:
    py portscan.py -dst_ip 192.168.207.42 -p 88 -sT
    py portscan.py -dst_ip 192.168.207.42 -p 88-92 -sT
    py portscan.py -dst_ip 192.168.207.42 -p 88,90,23 -sT
## UDP Scan
    py portscan.py -dst_ip 192.168.207.42 -p 88 -sU
    py portscan.py -dst_ip 192.168.207.42 -p 88-90 -sU
    py portscan.py -dst_ip 192.168.207.42 -p 88,90,23 -sU
## Ping Sweep Subnet
    py portscan.py -dst_ip 192.168.207.40/30 -ping
## Ping Sweep hosts from a txt file
    py portscan.py -f iplist.txt -ping
## Ping Sweep Comma Separated List
    py portscan.py -dst_ip 192.168.207.42,192.168.207.101,192.168.207.49 -ping

