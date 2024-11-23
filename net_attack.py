# Imports
import argparse
import os
import sys
from scapy.all import ICMP, IP, sr1, TCP
import socket
import requests

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

                if port == 22:
                    confirmSSH(target_ip)
                elif port == 80:
                    confirmHTTP(target_ip)

            elif tcp_response.flags == 0x14:  # RST-ACK (bitwise mask)
                print(f"{port:<8}{'Closed':<12}{service}")
        
        else:  # Unknown response
            print(f"{port:<8}{'Unknown':<12}{service}")

        


# Question 4: Confirm Service

def confirmSSH(target_ip): # Connect to port 22
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # New socket object for IPv4 TCP communication
        sock.settimeout(5)  # Set timeout to avoid delays if the port is closed
        sock.connect((target_ip, 22))
        banner = sock.recv(1024).decode('utf-8', errors='ignore') # Grab the banner & recieve 1024 bytes of data
        sock.close()
        
        if banner.startswith("SSH-"):
            print(f"SSH service confirmed on {target_ip}:22")
            print()
            return True
        else:
            print(f"No SSH banner found on {target_ip}:22")
            print()
            return False
   
    except (socket.timeout, socket.error):
        print(f"Unable to connect to {target_ip}:22")
        print()
        return False
    
def confirmHTTP(target_ip):
    try:
        # Send a basic HTTP GET request to port 80
        response = requests.get(f'http://{target_ip}', timeout=5)
        
        # Checking responses (200 is HTTP)
        if response.status_code == 200:
            print(f"HTTP service confirmed on {target_ip}:80")
            print()
            dirBuster(target_ip) # Question 5 addition to call Directory Buster
            return True
        else:
            print(f"Non-200 HTTP response on {target_ip}:80 - Status Code: {response.status_code}")
            print()
            return False
    
    except requests.RequestException:
        print(f"Unable to connect to {target_ip}:80")
        print()
        return False    
    
# Question 5: Directory Busting
def dirBuster(target_ip):
    print("\n[-] Starting directory busting for open port 80...")
    print("-" * 50)
    pages = [
        "login.php",
        "admin.php",
        "admin/login.php",
        "admin/admin.php",
    ] # Defines the pages to be checked

    for page in pages:
        url = f"http://{target_ip}/{page}" # Creates URL using target IP and checks for each page
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200: # Successful status code
                print(f"[+] Accessible: {url}")
                if "<form" in response.text.lower(): # Checks if form is present
                    print(f"    [+] HTML form found on: {url}")
                    print()
                else:
                    print(f"    [-] No HTML form found on: {url}")
                    print()
            else:
                print(f"[-] Not accessible: {url} (Status Code: {response.status_code})")
        except requests.RequestException as e:
            print(f"[-] Error accessing {url}: {e}")
    print()


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
