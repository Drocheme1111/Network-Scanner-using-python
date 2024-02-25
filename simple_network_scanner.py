#!/usr/bin/python3
import nmap

# Create a PortScanner object
nm = nmap.PortScanner()

# Prompt user for IP address or domain name
target = input("Enter the IP address or domain name to scan: ")

# Perform the scan
nm.scan(hosts=target, arguments='-sV')

# Iterate through scan results and print information
for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)  
        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            print('Port : %s\tState : %s\tService : %s\tVersion : %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name'], nm[host][proto][port]['version']))

