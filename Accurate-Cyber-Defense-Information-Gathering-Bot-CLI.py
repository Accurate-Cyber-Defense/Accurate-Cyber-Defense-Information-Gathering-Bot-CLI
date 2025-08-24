import socket
import threading
import time
import json
import os
import subprocess
import platform
import requests
import ipaddress
import concurrent.futures
from datetime import datetime
from collections import deque

class accurate:
    def __init__(self):
        self.monitoring = False
        self.monitoring_target = None
        self.monitoring_thread = None
        self.history = deque(maxlen=100)
        self.telegram_chat_id = None
        self.telegram_token = None
        self.vulnerability_db = self.load_vulnerability_db()
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080
        ]
        self.all_ports = list(range(1, 65536))
        self.scan_results = {}
        self.monitoring_log = []
        
    def load_vulnerability_db(self):
        # Simulated vulnerability database
        # In a real tool, this would be loaded from an external source
        return {
            '21': ['FTP Anonymous login', 'Weak encryption'],
            '22': ['SSH Weak algorithms', 'Brute force vulnerable'],
            '23': ['Telnet unencrypted communication', 'Brute force vulnerable'],
            '25': ['SMTP Open relay', 'Email spoofing'],
            '53': ['DNS Cache poisoning', 'DNS amplification'],
            '80': ['HTTP Vulnerabilities', 'Web application attacks'],
            '110': ['POP3 Clear text authentication'],
            '135': ['RPC Endpoint mapper vulnerabilities'],
            '139': ['NetBIOS Session service vulnerabilities'],
            '143': ['IMAP Clear text authentication'],
            '443': ['SSL/TLS vulnerabilities', 'Heartbleed'],
            '445': ['SMB vulnerabilities', 'EternalBlue'],
            '993': ['IMAPS Configuration issues'],
            '995': ['POP3S Configuration issues'],
            '1723': ['PPTP Vulnerabilities'],
            '3306': ['MySQL Weak authentication'],
            '3389': ['RDP Vulnerabilities', 'BlueKeep'],
            '5900': ['VNC Weak authentication'],
            '8080': ['HTTP Proxy misconfigurations']
        }
    
    def save_config(self):
        config = {
            'telegram_chat_id': self.telegram_chat_id,
            'telegram_token': self.telegram_token
        }
        with open('sentinelguard_config.json', 'w') as f:
            json.dump(config, f)
    
    def load_config(self):
        try:
            with open('sentinelguard_config.json', 'r') as f:
                config = json.load(f)
                self.telegram_chat_id = config.get('telegram_chat_id')
                self.telegram_token = config.get('telegram_token')
        except FileNotFoundError:
            pass
    
    def add_to_history(self, command):
        self.history.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {command}")
    
    def show_history(self):
        print("\nCommand History:")
        for i, cmd in enumerate(self.history, 1):
            print(f"{i}. {cmd}")
    
    def clear_screen(self):
        os.system('cls' if platform.system() == 'Windows' else 'clear')
    
    def ping_ip(self, ip):
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip]
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"\nPing to {ip} successful!")
                print(result.stdout)
            else:
                print(f"\nPing to {ip} failed.")
                print(result.stderr)
                
        except ValueError:
            print(f"Invalid IP address: {ip}")
        except Exception as e:
            print(f"Error during ping: {e}")
    
    def scan_port(self, ip, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return port, "Open"
                else:
                    return port, "Closed"
        except socket.gaierror:
            return port, "Hostname could not be resolved"
        except socket.error:
            return port, "Could not connect"
    
    def scan_ports(self, ip, ports, scan_type="normal"):
        print(f"\nStarting {scan_type} scan on {ip}...")
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port, status = future.result()
                    if status == "Open":
                        print(f"Port {port}: Open")
                        open_ports.append(port)
                except Exception as e:
                    print(f"Port {port} generated an exception: {e}")
        
        print(f"\nScan completed. Found {len(open_ports)} open ports.")
        self.scan_results[ip] = {
            'timestamp': datetime.now().isoformat(),
            'open_ports': open_ports,
            'scan_type': scan_type
        }
        return open_ports
    
    def deep_scan_ip(self, ip):
        return self.scan_ports(ip, self.all_ports, "deep")
    
    def normal_scan_ip(self, ip):
        return self.scan_ports(ip, self.common_ports, "normal")
    
    def get_location(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            
            if data['status'] == 'success':
                print(f"\nLocation information for {ip}:")
                print(f"Country: {data.get('country', 'N/A')}")
                print(f"Region: {data.get('regionName', 'N/A')}")
                print(f"City: {data.get('city', 'N/A')}")
                print(f"ZIP: {data.get('zip', 'N/A')}")
                print(f"Latitude: {data.get('lat', 'N/A')}")
                print(f"Longitude: {data.get('lon', 'N/A')}")
                print(f"ISP: {data.get('isp', 'N/A')}")
                print(f"Organization: {data.get('org', 'N/A')}")
                print(f"AS: {data.get('as', 'N/A')}")
            else:
                print(f"Could not retrieve location for {ip}: {data.get('message', 'Unknown error')}")
                
        except Exception as e:
            print(f"Error retrieving location: {e}")
    
    def check_vulnerabilities(self, ip):
        if ip not in self.scan_results:
            print(f"No scan results available for {ip}. Please scan first.")
            return
        
        open_ports = self.scan_results[ip]['open_ports']
        vulnerabilities = []
        
        print(f"\nChecking vulnerabilities for {ip} on open ports: {open_ports}")
        
        for port in open_ports:
            port_str = str(port)
            if port_str in self.vulnerability_db:
                vulns = self.vulnerability_db[port_str]
                vulnerabilities.extend([(port, vuln) for vuln in vulns])
                print(f"Port {port}: {', '.join(vulns)}")
        
        if not vulnerabilities:
            print("No known vulnerabilities found for open ports.")
        
        return vulnerabilities
    
    def send_telegram_alert(self, message):
        if not self.telegram_token or not self.telegram_chat_id:
            print("Telegram not configured. Use 'config telegram token' and 'config telegram chat_id' first.")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload)
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending Telegram alert: {e}")
            return False
    
    def monitor_target(self):
        print(f"Starting monitoring of {self.monitoring_target}")
        monitoring_start = datetime.now()
        check_count = 0
        
        while self.monitoring:
            check_count += 1
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Check if target is reachable
            try:
                # Quick port check on common ports
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    futures = [executor.submit(self.scan_port, self.monitoring_target, port, 2) 
                              for port in self.common_ports]
                
                open_ports = []
                for future in futures:
                    port, status = future.result()
                    if status == "Open":
                        open_ports.append(port)
                
                status_msg = f"Monitor check #{check_count} at {current_time}: {len(open_ports)} ports open"
                log_entry = {
                    'timestamp': current_time,
                    'open_ports': open_ports,
                    'status': 'UP' if open_ports else 'DOWN'
                }
                self.monitoring_log.append(log_entry)
                
                print(status_msg)
                
                # Send alert if status changes significantly
                if check_count > 1 and len(open_ports) != len(self.monitoring_log[-2]['open_ports']):
                    alert_msg = f"🚨 SentinelGuard Alert: Port change detected on {self.monitoring_target}\n"
                    alert_msg += f"Previous: {len(self.monitoring_log[-2]['open_ports'])} open ports\n"
                    alert_msg += f"Current: {len(open_ports)} open ports\n"
                    alert_msg += f"Time: {current_time}"
                    
                    self.send_telegram_alert(alert_msg)
                
            except Exception as e:
                error_msg = f"Monitor check #{check_count} at {current_time}: Error - {e}"
                print(error_msg)
                self.monitoring_log.append({
                    'timestamp': current_time,
                    'error': str(e),
                    'status': 'ERROR'
                })
            
            # Wait before next check
            time.sleep(60)
        
        monitoring_end = datetime.now()
        duration = monitoring_end - monitoring_start
        print(f"Monitoring stopped. Duration: {duration}")
    
    def start_monitoring(self, ip):
        if self.monitoring:
            print(f"Already monitoring {self.monitoring_target}. Stop first.")
            return
        
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            self.monitoring_target = ip
            self.monitoring = True
            self.monitoring_thread = threading.Thread(target=self.monitor_target)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            print(f"Started monitoring {ip}")
        except ValueError:
            print(f"Invalid IP address: {ip}")
    
    def stop_monitoring(self):
        if not self.monitoring:
            print("No active monitoring to stop.")
            return
        
        self.monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        print("Monitoring stopped.")
    
    def view_monitoring_log(self):
        if not self.monitoring_log:
            print("No monitoring data available.")
            return
        
        print("\nMonitoring Log:")
        for entry in self.monitoring_log:
            timestamp = entry.get('timestamp', 'N/A')
            status = entry.get('status', 'N/A')
            if 'open_ports' in entry:
                ports = entry['open_ports']
                print(f"{timestamp} - Status: {status} - Open ports: {ports}")
            else:
                error = entry.get('error', 'Unknown error')
                print(f"{timestamp} - Status: {status} - Error: {error}")
    
    def show_status(self):
        print("\nSentinelGuard Status:")
        print(f"Monitoring: {'Active' if self.monitoring else 'Inactive'}")
        if self.monitoring:
            print(f"Monitoring target: {self.monitoring_target}")
        print(f"Telegram configured: {'Yes' if self.telegram_token and self.telegram_chat_id else 'No'}")
        print(f"Commands in history: {len(self.history)}")
        print(f"Vulnerabilities in database: {sum(len(v) for v in self.vulnerability_db.values())}")
    
    def config_telegram(self, config_type, value):
        if config_type == "token":
            self.telegram_token = value
            print("Telegram token configured.")
        elif config_type == "chat_id":
            self.telegram_chat_id = value
            print("Telegram chat ID configured.")
        else:
            print("Invalid configuration type. Use 'token' or 'chat_id'.")
        
        self.save_config()
    
    def show_help(self):
        print("""
Accurate Cyber Defense  - Cyber Security Tool Commands:

help                         Show this help message
ping <ip>                    Ping an IP address to check connectivity
scan <ip>                    Scan common ports on an IP address
deep scan <ip>               Perform a deep scan of all ports on an IP address
start monitoring <ip>        Start continuous monitoring of an IP address
stop                         Stop monitoring
view                         View monitoring log
status                       Show current tool status
location <ip>                Get geographical location of an IP address
vulnerabilities <ip>         Check for vulnerabilities on scanned IP
history                      Show command history
config telegram token <token> Configure Telegram bot token
config telegram chat_id <id> Configure Telegram chat ID
clear                        Clear the screen
exit                         Exit the tool
        """)
    
    def run(self):
        self.load_config()
        self.clear_screen()
        
        print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║          WELCOME TO ACCURATE CYBER DEFENSE                                 
               Author: Ian Carter Kulani                                  
    ║          E-mail:iancarterkulani@gmail.com                             
               Community: https://github.com/Accurate-Cyber-Defense
    ╚══════════════════════════════════════════════════════════════╝
        """)
        
        while True:
            try:
                command = input("\nAccuratebot> ").strip()
                if not command:
                    continue
                
                self.add_to_history(command)
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == "exit":
                    self.stop_monitoring()
                    print("Exiting Accurate Bot. Stay secure!")
                    break
                
                elif cmd == "help":
                    self.show_help()
                
                elif cmd == "clear":
                    self.clear_screen()
                
                elif cmd == "history":
                    self.show_history()
                
                elif cmd == "status":
                    self.show_status()
                
                elif cmd == "view":
                    self.view_monitoring_log()
                
                elif cmd == "stop":
                    self.stop_monitoring()
                
                elif cmd == "ping" and len(parts) > 1:
                    self.ping_ip(parts[1])
                
                elif cmd == "scan" and len(parts) > 1:
                    self.normal_scan_ip(parts[1])
                
                elif cmd == "deep" and len(parts) > 2 and parts[1] == "scan":
                    self.deep_scan_ip(parts[2])
                
                elif cmd == "start" and len(parts) > 2 and parts[1] == "monitoring":
                    self.start_monitoring(parts[2])
                
                elif cmd == "location" and len(parts) > 1:
                    self.get_location(parts[1])
                
                elif cmd == "vulnerabilities" and len(parts) > 1:
                    self.check_vulnerabilities(parts[1])
                
                elif cmd == "config" and len(parts) > 3 and parts[1] == "telegram":
                    self.config_telegram(parts[2], parts[3])
                
                else:
                    print("Unknown command. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the tool.")
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    tool = accurate()
    tool.run()