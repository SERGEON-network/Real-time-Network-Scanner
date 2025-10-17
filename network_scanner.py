#!/usr/bin/env python3
"""
REAL WIFI NETWORK MONITOR - Shows Actual WiFi Devices
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
import time
import socket
import threading
import subprocess
import platform
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque, defaultdict
from datetime import datetime, timedelta
import os
import sys
import ipaddress
import netifaces
import re

class RealWiFiMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("REAL WIFI NETWORK MONITOR - ACTUAL DEVICES")
        self.root.geometry("1600x1000")
        self.root.configure(bg='#0a0a1a')
        
        # Data storage
        self.devices = {}
        self.connection_history = deque(maxlen=1000)
        
        # Chart data
        self.chart_timestamps = deque(maxlen=30)
        self.download_speeds = deque(maxlen=30)
        self.upload_speeds = deque(maxlen=30)
        
        # Setup GUI
        self.setup_gui()
        self.setup_styles()
        
        # Initialize chart data
        self.init_chart_data()
        
        # Get real network info
        self.get_real_network_info()

    def init_chart_data(self):
        """Initialize chart data with zeros"""
        current_time = datetime.now()
        for i in range(30):
            timestamp = current_time - timedelta(seconds=(29-i))
            self.chart_timestamps.append(timestamp)
            self.download_speeds.append(0)
            self.upload_speeds.append(0)

    def setup_styles(self):
        """Configure modern dark theme styles"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure('Header.TLabel', 
                           background='#1a1a2e',
                           foreground='white',
                           font=('Arial', 14, 'bold'))
        
        self.style.configure('Card.TFrame',
                           background='#16213e',
                           relief='raised',
                           borderwidth=1)

    def setup_gui(self):
        """Setup the main GUI layout"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.setup_header(main_frame)
        
        # Content area
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Left panel - Devices
        left_frame = ttk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Right panel - Charts and info
        right_frame = ttk.Frame(content_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Setup panels
        self.setup_devices_panel(left_frame)
        self.setup_charts_panel(right_frame)
        self.setup_info_panel(right_frame)
        
        # Status bar
        self.setup_status_bar()

    def setup_header(self, parent):
        """Setup header with controls"""
        header_frame = ttk.Frame(parent, style='Card.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_frame = ttk.Frame(header_frame, style='Card.TFrame')
        title_frame.pack(fill=tk.X, padx=15, pady=10)
        
        title_label = ttk.Label(title_frame, 
                               text="📡 REAL WIFI NETWORK MONITOR - ACTUAL DEVICES", 
                               style='Header.TLabel')
        title_label.pack(side=tk.LEFT)
        
        self.network_info_label = ttk.Label(title_frame,
                                           text="Scanning network...",
                                           background='#16213e',
                                           foreground='#8888ff',
                                           font=('Arial', 10))
        self.network_info_label.pack(side=tk.LEFT, padx=(20, 0))
        
        # Control buttons
        control_frame = ttk.Frame(header_frame, style='Card.TFrame')
        control_frame.pack(fill=tk.X, padx=15, pady=(0, 10))
        
        ttk.Button(control_frame,
                  text="🔍 Scan Real Devices",
                  command=self.scan_real_devices,
                  style='Card.TFrame').pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(control_frame,
                  text="🔄 Refresh",
                  command=self.scan_real_devices,
                  style='Card.TFrame').pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(control_frame,
                  text="📊 Show Connections",
                  command=self.show_real_connections,
                  style='Card.TFrame').pack(side=tk.LEFT)

    def setup_devices_panel(self, parent):
        """Setup devices display panel"""
        frame = ttk.LabelFrame(parent, text="🖥️ REAL NETWORK DEVICES", style='Card.TFrame')
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Devices treeview
        columns = ('IP Address', 'MAC Address', 'Hostname', 'Vendor', 'Status', 'Response Time')
        self.devices_tree = ttk.Treeview(frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        column_widths = {
            'IP Address': 150, 'MAC Address': 150, 'Hostname': 200, 
            'Vendor': 200, 'Status': 100, 'Response Time': 120
        }
        for col in columns:
            self.devices_tree.heading(col, text=col)
            self.devices_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=scrollbar.set)
        
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

    def setup_charts_panel(self, parent):
        """Setup charts panel"""
        frame = ttk.LabelFrame(parent, text="📊 NETWORK TRAFFIC", style='Card.TFrame')
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Create matplotlib figure
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 8))
        self.fig.patch.set_facecolor('#16213e')
        
        # Configure subplots
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('#1a1a2e')
            ax.tick_params(colors='white', labelsize=8)
            ax.grid(True, alpha=0.3, color='#444444')
            for spine in ax.spines.values():
                spine.set_color('#444444')
        
        self.ax1.set_title('Real Network Throughput', color='white', fontsize=10, pad=10)
        self.ax1.set_ylabel('Download (MB/s)', color='white', fontsize=9)
        
        self.ax2.set_title('Upload Speed', color='white', fontsize=10, pad=10)
        self.ax2.set_ylabel('Upload (MB/s)', color='white', fontsize=9)
        self.ax2.set_xlabel('Time', color='white', fontsize=9)
        
        # Embed in tkinter
        self.canvas = FigureCanvasTkAgg(self.fig, frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_info_panel(self, parent):
        """Setup information panel"""
        frame = ttk.LabelFrame(parent, text="🔍 SCAN RESULTS", style='Card.TFrame')
        frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        self.info_text = scrolledtext.ScrolledText(frame,
                                                  bg='#1a1a2e',
                                                  fg='white',
                                                  font=('Courier', 9),
                                                  height=15)
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.info_text.config(state=tk.DISABLED)

    def setup_status_bar(self):
        """Setup status bar"""
        status_frame = ttk.Frame(self.root, relief=tk.SUNKEN, style='Card.TFrame')
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(status_frame, 
                                     text="Ready to scan real network devices...", 
                                     background='#16213e', foreground='white')
        self.status_label.pack(side=tk.LEFT, padx=10, pady=2)

    def get_real_network_info(self):
        """Get real network information"""
        try:
            # Get default gateway and network info
            gateways = netifaces.gateways()
            if netifaces.AF_INET in gateways['default']:
                gateway_info = gateways['default'][netifaces.AF_INET]
                gateway_ip = gateway_info[0]
                interface = gateway_info[1]
                
                # Get network addresses
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip_address = ip_info['addr']
                    netmask = ip_info['netmask']
                    
                    # Calculate network range
                    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                    network_range = str(network)
                    
                    self.network_info_label.config(
                        text=f"Network: {network_range} | Gateway: {gateway_ip} | Interface: {interface}"
                    )
                    
                    self.log_info(f"Real network detected: {network_range}")
                    self.log_info(f"Your IP: {ip_address}, Gateway: {gateway_ip}")
                    
        except Exception as e:
            self.log_info(f"Error detecting network: {str(e)}")

    def scan_real_devices(self):
        """Scan for real network devices"""
        self.status_label.config(text="Scanning for real network devices...")
        self.log_info("Starting real network scan...")
        
        def scan_thread():
            try:
                # Clear previous results
                self.devices.clear()
                
                # Method 1: Use system ARP table (most reliable)
                self.log_info("Method 1: Reading system ARP table...")
                self.scan_arp_table()
                
                # Method 2: Use nmap for active discovery
                self.log_info("Method 2: Active network discovery...")
                self.scan_with_nmap()
                
                # Method 3: Use ip neigh (Linux)
                if platform.system() == "Linux":
                    self.log_info("Method 3: Checking neighbor table...")
                    self.scan_ip_neigh()
                
                # Update display
                self.root.after(0, self.update_devices_display)
                self.root.after(0, self.scan_complete)
                
            except Exception as e:
                self.root.after(0, lambda: self.scan_error(str(e)))
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def scan_arp_table(self):
        """Scan system ARP table for real devices"""
        try:
            if platform.system() == "Linux":
                # Linux ARP table
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                self.parse_linux_arp(result.stdout)
            else:
                # Windows ARP table
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                self.parse_windows_arp(result.stdout)
                
        except Exception as e:
            self.log_info(f"ARP table scan error: {str(e)}")

    def parse_linux_arp(self, output):
        """Parse Linux ARP table output"""
        lines = output.split('\n')
        devices_found = 0
        
        for line in lines:
            # Linux format: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on wlan0
            if '(' in line and ')' in line and 'at' in line:
                try:
                    # Extract IP address
                    ip_start = line.find('(') + 1
                    ip_end = line.find(')')
                    ip = line[ip_start:ip_end]
                    
                    # Extract MAC address
                    mac_start = line.find('at') + 3
                    mac_end = line.find(' ', mac_start)
                    if mac_end == -1:
                        mac_end = line.find('[', mac_start)
                    mac = line[mac_start:mac_end].strip()
                    
                    # Extract hostname
                    hostname_start = 0
                    hostname_end = line.find('(')
                    hostname = line[hostname_start:hostname_end].strip()
                    
                    if self.is_valid_ip(ip) and self.is_valid_mac(mac):
                        vendor = self.get_vendor_from_mac(mac)
                        self.add_real_device(ip, mac, hostname, vendor)
                        devices_found += 1
                        self.log_info(f"Found: {ip} -> {mac} ({hostname})")
                        
                except Exception as e:
                    continue
        
        self.log_info(f"ARP table: Found {devices_found} devices")

    def parse_windows_arp(self, output):
        """Parse Windows ARP table output"""
        lines = output.split('\n')
        devices_found = 0
        
        for line in lines:
            # Windows format: 192.168.1.1          00-11-22-33-44-55     dynamic
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1].replace('-', ':')
                
                if self.is_valid_ip(ip) and self.is_valid_mac(mac):
                    hostname = self.get_hostname(ip)
                    vendor = self.get_vendor_from_mac(mac)
                    self.add_real_device(ip, mac, hostname, vendor)
                    devices_found += 1
                    self.log_info(f"Found: {ip} -> {mac} ({hostname})")
        
        self.log_info(f"ARP table: Found {devices_found} devices")

    def scan_with_nmap(self):
        """Use nmap for active network discovery"""
        try:
            # Get network range
            gateways = netifaces.gateways()
            gateway_ip = gateways['default'][netifaces.AF_INET][0]
            network_base = '.'.join(gateway_ip.split('.')[:3]) + '.0/24'
            
            self.log_info(f"Scanning network: {network_base}")
            
            # Quick ping sweep
            result = subprocess.run(['nmap', '-sn', network_base], 
                                  capture_output=True, text=True, timeout=30)
            
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Nmap scan report for' in line:
                    # Extract hostname and IP
                    parts = line.split()
                    if len(parts) >= 5:
                        hostname = parts[4] if '(' not in parts[4] else "Unknown"
                        ip = parts[-1].strip('()')
                        
                        if self.is_valid_ip(ip) and ip not in self.devices:
                            # Try to get MAC address for this IP
                            mac = self.get_mac_for_ip(ip)
                            vendor = self.get_vendor_from_mac(mac) if mac else "Unknown"
                            self.add_real_device(ip, mac or "Unknown", hostname, vendor)
                            
        except Exception as e:
            self.log_info(f"Nmap scan error: {str(e)}")

    def scan_ip_neigh(self):
        """Scan Linux ip neighbor table"""
        try:
            result = subprocess.run(['ip', 'neighbor', 'show'], 
                                  capture_output=True, text=True)
            
            lines = result.stdout.split('\n')
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    ip = parts[0]
                    mac = parts[4]
                    state = parts[5] if len(parts) > 5 else "UNKNOWN"
                    
                    if self.is_valid_ip(ip) and self.is_valid_mac(mac) and state == "REACHABLE":
                        if ip not in self.devices:
                            hostname = self.get_hostname(ip)
                            vendor = self.get_vendor_from_mac(mac)
                            self.add_real_device(ip, mac, hostname, vendor)
                            
        except Exception as e:
            self.log_info(f"IP neighbor scan error: {str(e)}")

    def get_mac_for_ip(self, ip):
        """Get MAC address for IP using ARP"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except:
            pass
        return None

    def get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:
                return hostname
                
            # Try reverse DNS
            result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if 'name =' in line:
                    return line.split('=')[1].strip()
                    
        except:
            pass
        return "Unknown"

    def get_vendor_from_mac(self, mac):
        """Get vendor from MAC address OUI"""
        if not mac or mac == "Unknown" or not self.is_valid_mac(mac):
            return "Unknown"
        
        # Common OUI prefixes (first 3 bytes of MAC)
        oui_db = {
            '00:1A:2B': 'Cisco', '00:50:56': 'VMware', '00:0C:29': 'VMware',
            '00:1B:44': 'Huawei', '00:1C:C4': 'HPE', '00:24:E8': 'Dell',
            '00:26:BB': 'Apple', '00:1D:72': 'Samsung', '00:23:AE': 'Google',
            '00:11:22': 'Samsung', '00:17:F2': 'Apple', '00:19:E3': 'D-Link',
            '00:1E:65': 'Netgear', '00:21:6A': 'Intel', '00:22:5F': 'Microsoft',
            '00:25:BC': 'ASUS', '00:26:5C': 'TP-Link', '00:50:BA': 'Microsoft',
            '00:1F:5B': 'Sony', '00:24:01': 'Raspberry Pi', '00:1C:B3': 'Dell',
            'AA:BB:CC': 'Example Corp', '11:22:33': 'Test Vendor'
        }
        
        mac_prefix = mac.upper()[:8]  # First 6 characters (OUI)
        return oui_db.get(mac_prefix, "Unknown Manufacturer")

    def add_real_device(self, ip, mac, hostname, vendor):
        """Add a real discovered device"""
        if ip not in self.devices:
            # Test if device is reachable
            status = self.test_device_reachability(ip)
            response_time = self.ping_device(ip)
            
            self.devices[ip] = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'status': status,
                'response_time': response_time,
                'last_seen': datetime.now()
            }

    def test_device_reachability(self, ip):
        """Test if device is reachable"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, timeout=2)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, timeout=2)
            
            return "Online" if result.returncode == 0 else "Offline"
        except:
            return "Unknown"

    def ping_device(self, ip):
        """Ping device and return response time"""
        try:
            start_time = time.time()
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, timeout=2)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, timeout=2)
            
            if result.returncode == 0:
                return round((time.time() - start_time) * 1000, 1)  # ms
        except:
            pass
        return 0

    def is_valid_ip(self, ip):
        """Check if IP address is valid"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except:
            return False

    def is_valid_mac(self, mac):
        """Check if MAC address is valid"""
        if not mac or mac == "Unknown":
            return False
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))

    def update_devices_display(self):
        """Update devices treeview with real data"""
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        for device_data in self.devices.values():
            status_icon = "🟢" if device_data['status'] == "Online" else "🔴"
            response_time = f"{device_data['response_time']}ms" if device_data['response_time'] > 0 else "N/A"
            
            self.devices_tree.insert('', 'end', values=(
                device_data['ip'],
                device_data['mac'],
                device_data['hostname'],
                device_data['vendor'],
                f"{status_icon} {device_data['status']}",
                response_time
            ))

    def show_real_connections(self):
        """Show real network connections"""
        self.log_info("Scanning real network connections...")
        
        try:
            connections = psutil.net_connections(kind='inet')
            self.log_info(f"Found {len(connections)} network connections")
            
            connection_count = 0
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    
                    process_name = "unknown"
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except:
                            pass
                    
                    self.log_info(f"Connection: {local_addr} -> {remote_addr} ({process_name})")
                    connection_count += 1
            
            self.log_info(f"Total established connections: {connection_count}")
            
        except Exception as e:
            self.log_info(f"Connection scan error: {str(e)}")

    def log_info(self, message):
        """Log information to the info panel"""
        self.root.after(0, lambda: self._add_to_info_panel(message))

    def _add_to_info_panel(self, message):
        """Add message to info panel (thread-safe)"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.info_text.config(state=tk.NORMAL)
        self.info_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.info_text.see(tk.END)
        self.info_text.config(state=tk.DISABLED)

    def scan_complete(self):
        """Handle scan completion"""
        self.status_label.config(text=f"Scan complete - Found {len(self.devices)} real devices")
        self.log_info(f"=== SCAN COMPLETE ===")
        self.log_info(f"Total real devices found: {len(self.devices)}")
        
        online_count = sum(1 for d in self.devices.values() if d['status'] == 'Online')
        self.log_info(f"Online devices: {online_count}")
        self.log_info(f"Offline devices: {len(self.devices) - online_count}")

    def scan_error(self, error):
        """Handle scan error"""
        self.status_label.config(text=f"Scan error: {error}")
        self.log_info(f"SCAN ERROR: {error}")

    def start_traffic_monitoring(self):
        """Start monitoring network traffic"""
        self.prev_net_io = psutil.net_io_counters()
        self.prev_time = time.time()
        
        def monitor_loop():
            while True:
                try:
                    self.update_traffic_data()
                    time.sleep(2)
                except Exception as e:
                    print(f"Traffic monitoring error: {e}")
                    time.sleep(5)
        
        threading.Thread(target=monitor_loop, daemon=True).start()

    def update_traffic_data(self):
        """Update network traffic data for charts"""
        try:
            current_net_io = psutil.net_io_counters()
            current_time = time.time()
            time_diff = current_time - self.prev_time
            
            if time_diff > 0:
                # Calculate speeds in MB/s
                download_speed = (current_net_io.bytes_recv - self.prev_net_io.bytes_recv) / (1024 * 1024 * time_diff)
                upload_speed = (current_net_io.bytes_sent - self.prev_net_io.bytes_sent) / (1024 * 1024 * time_diff)
                
                # Update chart data
                self.chart_timestamps.append(datetime.now())
                self.download_speeds.append(download_speed)
                self.upload_speeds.append(upload_speed)
                
                # Update charts
                self.root.after(0, self.update_charts)
                
                # Update for next iteration
                self.prev_net_io = current_net_io
                self.prev_time = current_time
                
        except Exception as e:
            print(f"Traffic update error: {e}")

    def update_charts(self):
        """Update the traffic charts"""
        try:
            self.ax1.clear()
            self.ax2.clear()
            
            if len(self.chart_timestamps) > 0:
                times = list(self.chart_timestamps)
                download = list(self.download_speeds)
                upload = list(self.upload_speeds)
                
                # Download chart
                self.ax1.plot(times, download, color='#00ff88', linewidth=2)
                self.ax1.set_title('Real Network Download', color='white', fontsize=10, pad=10)
                self.ax1.set_ylabel('MB/s', color='white', fontsize=9)
                self.ax1.tick_params(colors='white', labelsize=8)
                self.ax1.grid(True, alpha=0.3, color='#444444')
                
                # Upload chart
                self.ax2.plot(times, upload, color='#4488ff', linewidth=2)
                self.ax2.set_title('Real Network Upload', color='white', fontsize=10, pad=10)
                self.ax2.set_ylabel('MB/s', color='white', fontsize=9)
                self.ax2.set_xlabel('Time', color='white', fontsize=9)
                self.ax2.tick_params(colors='white', labelsize=8)
                self.ax2.grid(True, alpha=0.3, color='#444444')
            
            # Set background colors
            for ax in [self.ax1, self.ax2]:
                ax.set_facecolor('#1a1a2e')
                for spine in ax.spines.values():
                    spine.set_color('#444444')
            
            self.canvas.draw()
            
        except Exception as e:
            print(f"Chart update error: {e}")

def main():
    """Main application entry point"""
    try:
        # Check if we have required permissions
        if platform.system() == "Linux" and os.geteuid() != 0:
            print("⚠ Running without root privileges. Some features may not work.")
            print("   For best results, run with: sudo python3 real_wifi_network_monitor.py")
        
        root = tk.Tk()
        app = RealWiFiMonitor(root)
        
        # Start traffic monitoring
        app.start_traffic_monitoring()
        
        # Auto-scan on startup
        app.scan_real_devices()
        
        root.mainloop()
        
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Error", f"Failed to start application: {e}")

if __name__ == "__main__":
    main()
