# Imports
import argparse
import os
import sys
from scapy.all import ICMP, IP, sr1

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


# Question 1: Argparse
def main():
    print("Credential Checker:") 
    print("-" * 70)        
    
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
        type=int, 
        required=True, 
        help="Specify the target port number."
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
    print("\nChecking connectivity to the target IP...")
    if not checkConnectivity(args.target): # if false
        print(f"Error: Target {args.target} is unreachable.")
        sys.exit(1)
    else:
        print(f"Success: Target {args.target} is reachable.")    


    # Display parsed arguments on console
    print(f"Target IP Address: {args.target}") # f-string to include variable in string
    print(f"Ports to Scan: {args.port}")
    print(f"Username: {args.username}")
    print(f"Password List File: {args.password_list}")

if __name__ == "__main__":
    main()
