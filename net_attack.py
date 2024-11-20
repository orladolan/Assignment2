# Imports
import argparse
import os
import sys

# Question 1: Argparse
def main():
    print("Credential Checker:") 
    print("-" * 70)        
    
    parser = argparse.ArgumentParser(prog="net_attack.py", description="Read User Arguments"
                                     , epilog="Author: Orla Dolan")

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

    # Parsing the arguments to a variable
    args = parser.parse_args()

    # Display parsed arguments on console
    print(f"Target IP Address: {args.target}") # f-string to include variable in string
    print(f"Ports to Scan: {args.port}")
    print(f"Username: {args.username}")
    print(f"Password List File: {args.password_list}")

if __name__ == "__main__":
    main()
