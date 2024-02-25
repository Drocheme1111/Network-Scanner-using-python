# Network-Scanner-using-python
This Python script efficiently utilizes the Nmap library to perform network scans and retrieve detailed information about the target hosts, making it a valuable tool for network administrators and security professionals.


    The script starts by importing the nmap library, which provides functionalities for network scanning.
    An instance of PortScanner is created using nmap.PortScanner().
    The user is prompted to enter the target IP address or domain name to scan.
    The scan method is called on the PortScanner object nm with the target and scan arguments (-sV for service version detection).
    The script then iterates through all hosts in the scan results and prints information about each host, including hostname, state, protocols, ports, states, services, and versions.
    The information is displayed in a structured format for easy interpretation of the scan results.
