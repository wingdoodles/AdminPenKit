import nmap
import socket
import threading
import subprocess
import ipaddress
import time
import psutil
import time
import netifaces
from scapy.all import sniff
from collections import deque
from adminpenkit.modules.base_module import BaseModule
from adminpenkit.core.performance import measure_execution_time, cached_operation
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

class NetworkScanner(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Network Scanner"
        self._cache = {}
        self.scanner = nmap.PortScanner()
        self.target = None

    def initialize(self):
        """Initialize network scanner"""
        return True

    @measure_execution_time
    def execute(self, target_ip=None):
        self.target = target_ip or '127.0.0.1'
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.scan_target): "network_map",
                executor.submit(self.get_active_hosts): "active_hosts",
                executor.submit(self.scan_common_ports): "open_ports",
                executor.submit(self.get_network_interfaces): "interfaces"
            }
            
            results = {}
            for future in futures:
                key = futures[future]
                results[key] = future.result()
            
            return results

    def cleanup(self):
        """Cleanup scanner resources"""
        self.results = []
        return True

    def scan_target(self, target_ip, timeout=60):
        self.target = target_ip
        try:
            # For subnet scans, use more aggressive discovery
            if '/' in target_ip:
                arguments = '-T4 -sn -PE -n --min-parallelism 100'
            else:
                arguments = '-T4 -F -sV --max-retries 1'
                
            print(f"Starting scan of {target_ip}")  # Debug feedback
            scan_result = self.scanner.scan(self.target, arguments=arguments, timeout=timeout)
            print("Scan completed")  # Debug feedback
            
            results = []
            if 'scan' in scan_result:
                for host in scan_result['scan']:
                    host_info = {
                        'ip': host,
                        'hostname': scan_result['scan'][host].get('hostnames', [{'name': ''}])[0]['name'],
                        'state': scan_result['scan'][host]['status']['state']
                    }
                    results.append(host_info)
                    
            print(f"Found {len(results)} hosts")  # Debug feedback
            return results
                
        except Exception as e:
            print(f"Scan error: {str(e)}")  # Debug feedback
            return [{'ip': target_ip, 'state': 'error', 'message': str(e)}]
        
    def get_network_interfaces(self):
        interfaces = []
        for interface in socket.if_nameindex():
            interfaces.append(interface[1])
        return interfaces

    def get_active_hosts(self):
        active_hosts = []
        try:
            network = ipaddress.ip_network(f"{self.target}/24")
            for ip in network:
                if self.ping_host(str(ip)):
                    active_hosts.append(str(ip))
        except Exception:
            pass
        return active_hosts

    def ping_host(self, ip):
        try:
            subprocess.check_output(['ping', '-c', '1', '-W', '1', ip], 
                                 stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def scan_common_ports(self):
        common_ports = [80, 443, 22, 21]
        open_ports = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
            
        return open_ports


class NetworkInterfaceMonitor:
    def __init__(self):
        self.scanner = NetworkScanner()
        self._packet_buffer = deque(maxlen=100)
        self._lock = threading.Lock()
        self._capture_thread = None
        self._running = False
        self._last_bytes = {}
        self._last_check = time.time()
        
    def get_network_interfaces(self):
        """Direct method to get network interfaces"""
        return self.scanner.get_network_interfaces()
        
    def get_interface_details(self):
        """Get detailed information for each interface"""
        interfaces = self.get_network_interfaces()
        details = {}
        
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            stats = psutil.net_io_counters(pernic=True).get(interface)
            
            if stats:
                details[interface] = {
                    'status': {
                        'state': 'Up' if self._is_interface_up(interface) else 'Down',
                        'speed': self._get_interface_speed(interface),
                        'duplex': 'Full'
                    },
                    'statistics': {
                        'rx_bytes': stats.bytes_recv,
                        'tx_bytes': stats.bytes_sent,
                        'rx_packets': stats.packets_recv,
                        'tx_packets': stats.packets_sent,
                        'errors': stats.errin + stats.errout,
                        'drops': stats.dropin + stats.dropout
                    }
                }
        return details
        
    def _is_interface_up(self, interface):
        try:
            addr = netifaces.ifaddresses(interface)
            return netifaces.AF_INET in addr
        except ValueError:
            return False
            
    def _get_interface_speed(self, interface):
        # Default to 1Gbps when real speed can't be determined
        return 'Not Found'
        
    def start_capture(self, interface):
        """Start background packet capture"""
        if not self._running:
            self._running = True
            self._capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(interface,),
                daemon=True
            )
            self._capture_thread.start()
            
    def _capture_packets(self, interface):
        def packet_handler(pkt):
            if 'IP' in pkt and self._running:
                with self._lock:
                    self._packet_buffer.append({
                        'local_address': f"{pkt['IP'].src}",
                        'remote_address': f"{pkt['IP'].dst}",
                        'protocol': self._get_protocol(pkt),
                        'status': 'ACTIVE',
                        'pid': '-',
                        'program': '-'
                    })
        
        sniff(iface=interface, prn=packet_handler, store=0)
        
    def get_active_connections(self, interface):
        """Get current connections from buffer"""
        if not self._running:
            self.start_capture(interface)
            
        with self._lock:
            return list(self._packet_buffer)
            
    def _get_protocol(self, pkt):
        """Fast protocol detection"""
        if 'TCP' in pkt: return 'TCP'
        if 'UDP' in pkt: return 'UDP'
        if 'ICMP' in pkt: return 'ICMP'
        return 'OTHER'

    def monitor_interfaces(self):
        """Combined monitoring method"""
        return {
            'interfaces': self.get_interface_details(),
            'active_hosts': self.scanner.get_active_hosts()
        }

    def get_bandwidth_usage(self, interface):
        """Get real bandwidth usage for an interface"""
        current_time = time.time()
        stats = psutil.net_io_counters(pernic=True).get(interface)
        
        if interface not in self._last_bytes:
            self._last_bytes[interface] = stats
            self._last_check = current_time
            return {
                'timestamp': current_time,
                'bytes_recv_per_sec': 0,
                'bytes_sent_per_sec': 0,
                'total_bytes_per_sec': 0
            }
            
        time_delta = current_time - self._last_check
        bytes_recv = stats.bytes_recv - self._last_bytes[interface].bytes_recv
        bytes_sent = stats.bytes_sent - self._last_bytes[interface].bytes_sent
        
        self._last_bytes[interface] = stats
        self._last_check = current_time
        
        return {
            'timestamp': current_time,
            'bytes_recv_per_sec': bytes_recv / time_delta,
            'bytes_sent_per_sec': bytes_sent / time_delta,
            'total_bytes_per_sec': (bytes_recv + bytes_sent) / time_delta
        }
