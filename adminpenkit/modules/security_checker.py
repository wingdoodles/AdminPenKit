import os
import socket
import platform
import subprocess
from modules.base_module import BaseModule

class SecurityChecker(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Security Checker"
        
    def initialize(self):
        return True
        
    def execute(self):
        return self.run_security_checks()
        
    def cleanup(self):
        return True
        
    def run_security_checks(self):
        results = {
            "open_ports": self.check_open_ports(),
            "system_updates": self.check_system_updates(),
            "firewall_status": self.check_firewall(),
            "user_accounts": self.check_user_accounts()
        }
        return results
        
    def check_open_ports(self):
        common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432]
        open_ports = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
        
    def check_system_updates(self):
        system = platform.system().lower()
        if system == 'linux':
            try:
                output = subprocess.check_output(['apt', 'list', '--upgradable'])
                return len(output.decode().split('\n')) - 2
            except:
                return "Unable to check updates"
        return "Update check not implemented for this OS"
        
    def check_firewall(self):
        system = platform.system().lower()
        if system == 'linux':
            try:
                output = subprocess.check_output(['ufw', 'status'])
                return output.decode().strip()
            except:
                return "Firewall status unknown"
        return "Firewall check not implemented for this OS"
        
    def check_user_accounts(self):
        users = []
        if platform.system().lower() == 'linux':
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if '/bin/bash' in line or '/bin/sh' in line:
                        users.append(line.split(':')[0])
        return users
