import nmap
import socket
import threading
from adminpenkit.modules.base_module import BaseModule

class NetworkScanner(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Network Scanner"
        self.scanner = nmap.PortScanner()
        self.results = []
        
    def initialize(self):
        """Initialize network scanner"""
        return True
        
    def execute(self):
        """Execute network scan"""
        return self.scan_network()
        
    def cleanup(self):
        """Cleanup scanner resources"""
        self.results = []
        return True
        
    def scan_network(self, target_ip="127.0.0.1", ports="1-1024"):
        
        def scan_thread():
            try:
                return self.scanner.scan(target_ip, ports, arguments='-T4')
            except Exception as e:
                return {"error": str(e)}
                
        # Run scan in separate thread
        scan_thread = threading.Thread(target=scan_thread)
        scan_thread.daemon = True
        scan_thread.start()

        return self.format_results()            
    def format_results(self):
        results = []
        for host in self.scanner.all_hosts():
            host_info = {
                "ip": host,
                "hostname": self.scanner[host].hostname(),
                "state": self.scanner[host].state(),
                "ports": []
            }
            
            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in ports:
                    port_info = self.scanner[host][proto][port]
                    host_info["ports"].append({
                        "port": port,
                        "state": port_info["state"],
                        "service": port_info["name"]
                    })
            results.append(host_info)
        return results