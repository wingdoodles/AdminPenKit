import nmap
import socket
import threading
import subprocess
import ipaddress
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

    def scan_target(self, target_ip=None):
        self.target = target_ip or '127.0.0.1'
        try:
            scan_result = self.scanner.scan(self.target, arguments='-p 1-1024 -T4')
            results = []
            
            for host in scan_result['scan']:
                host_info = {
                    'ip': host,
                    'hostname': scan_result['scan'][host].get('hostnames', [{'name': ''}])[0]['name'],
                    'state': scan_result['scan'][host]['status']['state'],
                    'ports': []
                }
                
                if 'tcp' in scan_result['scan'][host]:
                    for port, port_info in scan_result['scan'][host]['tcp'].items():
                        host_info['ports'].append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name']
                        })
                        
                results.append(host_info)
            return results
            
        except Exception as e:
            return [{'error': str(e)}]
    @lru_cache(maxsize=32)
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