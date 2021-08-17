
# Things to work on:
# 1. Restart Program after invalid input
# 2. 


import nmap


scanner = nmap.PortScanner()

print("""

                          * * *
***********************************************************
**                                                       **
**                                                       **
**     Welcome to...                                     **
**                                                       **
**            _                  __  __                  **
**           | |                |  \/  |                 **
**       __ _| | ___ _ __  _ __ | \  / | __ _ _ __       **
**      / _` | |/ _ \ '_ \| '_ \| |\/| |/ _` | '_ \      **
**     | (_| | |  __/ | | | | | | |  | | (_| | |_) |     **
**      \__, |_|\___|_| |_|_| |_|_|  |_|\__,_| .__/      **
**       __/ |                               | |         **
**      |___/                    by SKiTSO   |_|         **
**                                                       **
**                                                       **
**                                                       **
**                 Network Mapping Tool                  **
**                                                       **
**                                                       **
***********************************************************
                          * * *

 """)
ip_addr = input("Please enter the IP address you want to scan: ")
print("\nThe IP address you entered is: ", ip_addr)
type(ip_addr)
resp = input("""\nPlease enter the type of scan you want to run:

        1. SYN ACK Scan 
        2. UDP Scan
        3. Comprehensive Scan\n """)
if resp == '1':
    print("You have selected option: ", resp)
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("You have selected option: ", resp)
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("You have selected option: ", resp)
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif type(resp) != 'int':
    print("Please enter a valid option.\n")
elif resp =='4':
    print("Please enter a valid option.\n")
