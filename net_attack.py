# Imports
import argparse
import os
import sys

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


    # Display parsed arguments on console
    print(f"Target IP Address: {args.target}") # f-string to include variable in string
    print(f"Ports to Scan: {args.port}")
    print(f"Username: {args.username}")
    print(f"Password List File: {args.password_list}")

if __name__ == "__main__":
    main()
