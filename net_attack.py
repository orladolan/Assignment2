# Imports
import argparse
import os
import sys
from scapy.all import ICMP, IP, sr1, TCP

# Question 2: Connectivity

def checkConnectivity(target_ip):
    # Creates the packet
    packet = IP(dst=target_ip)/ICMP()

    # Sends the packet and waits for a reply 
    reply = sr1(packet, timeout=5, verbose=0) # verbosity set to 0 to avoid unnecessary output

    if reply:  
        return True # If a reply does come back
    else:
        return False

# Question 3: Port Scan

def getPortServices(port):
    # Dictionary of services
        service = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            8080: "HTTP Proxy"
        }
        return service.get(port,"Unavailable")


def scanPorts(target_ip, target_ports):
   
    print(f"\n[+] Performing Port Scan on {target_ip}...") # F-String to include arg
    print(f"{'Port':<8}{'Status':<12}{'Service'}") # Titles
    print("-" * 50)

    ipHeader = IP(dst=target_ip)  

    for port in target_ports:
        # Create the TCP header with the port
        tcpHeader = TCP(dport=port, )
        packet = ipHeader / tcpHeader # Craft packet with both IP and TCP header

        # Send the packet and wait for a response
        response = sr1(packet, timeout=2, verbose=0)

        # Determine the port status based on the response
        service = getPortServices(port)
        
        if response is None:  # No response received
            print(f"{port:<8}{'No Response':<12}{service}")
        
        elif response.haslayer(TCP):  # TCP response received
            tcp_response = response.getlayer(TCP)

            if tcp_response.flags == 0x12:  # SYN-ACK (bitwise mask)
                print(f"{port:<8}{'Open':<12}{service}")

            elif tcp_response.flags == 0x14:  # RST-ACK (bitwise mask)
                print(f"{port:<8}{'Closed':<12}{service}")
        
        else:  # Unknown response
            print(f"{port:<8}{'Unknown':<12}{service}")





# Question 1: Argparse
def main():
    print("Credential Checker:") 
    print("-" * 50)       
    
    parser = argparse.ArgumentParser(prog="net_attack.py", description="Read User Arguments"
                                     , epilog="Author: Orla Dolan",)

    parser.add_argument(
        "-u", "--username", 
        type=str, 
        required=True, 
        help="Provide username."
    )
    parser.add_argument(
        "-t", "--target", 
        type=str, 
        required=True, 
        help="Specify the target IP address."
    )
    parser.add_argument(
        "-p", "--port", 
        type=str, 
        required=True, 
        help="Specify the target port numbers split with commas (e.g. 22,443,8080)."
    )
    parser.add_argument(
        "-l", "--password-list", 
        type=str, 
        required=True, 
        help="Specify the password list filename."
    )
  
    # Check if arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()  
        sys.exit(1)

    # Parsing the arguments to a variable
    try:
        args = parser.parse_args()  
    except SystemExit: # Catches SystemExit raised by argparse due to missing required values
        parser.print_help()
        sys.exit(1)


    # Task 2: Connectivity Check
    print("\n[+] Checking connectivity to the target IP...")
    print("-" * 50)
    if not checkConnectivity(args.target): # if false
        print(f"Error: Target {args.target} is unreachable.")
        sys.exit(1)
    else:
        print(f"Success: Target {args.target} is reachable.")    


    # Task 3: Scan Ports
    try:
        target_ports = [int(port.strip()) for port in args.port.split(",")]
    except ValueError:
        print("Error: Invalid port list format. Use comma-separated integers (e.g., 22,443,8080).")
        sys.exit(1)

    scanPorts(args.target, target_ports)

    # Display parsed arguments on console
    print("\n[+] Arguments Summary:")
    print("-" * 50)
    print(f"Target IP Address: {args.target}") # F-String to include variable in string
    print(f"Ports to Scan: {', '.join(map(str, target_ports))}") # Allows for multiple ports
    print(f"Username: {args.username}")
    print(f"Password List File: {args.password_list}")

if __name__ == "__main__":
    main()
