# Red-Team-Python
RedTeam Python
Description:
RedTeam Python is a Python script designed for network reconnaissance and basic penetration testing tasks. It provides a set of functions for different types of operations, including port scanning, network scanning, ARP (Address Resolution Protocol) manipulation, HTTP slow attacks, and deauthentication attacks.

Features:
Port Scanning (PS): Identify open ports on a target machine.

Network Scanning (NS): Discover live hosts on a network using ARP requests.

ARP Manipulation (ARP): Perform ARP poisoning to intercept network traffic between a victim machine and the gateway.

HTTP Slow Attack (HTTP): Initiate a slow HTTP attack by creating multiple sockets and sending HTTP requests.

Deauthentication Attack (Deauth): Conduct a deauthentication attack on a specified router and target machine.
Usage

To use the script, run it with elevated privileges (sudo) and choose a specific type of function using the -T or --Type option. Additional options such as target IP address (-A), number of sockets (-s), interface (-i), and port range (-1 and -2) can be specified based on the chosen function.

Disclaimer
This code is provided for educational purposes only. Please use it responsibly and ensure that you have appropriate authorization before conducting any penetration testing activities.

Author
AsoMoe - https://github.com/AsoMoe/Red-Team-Python

