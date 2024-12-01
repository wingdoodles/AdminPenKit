from adminpenkit.modules.base_module import BaseModule
import nmap
import socket
import psutil
import platform
import subprocess

class SecurityAudit(BaseModule):
    def __init__(self):
        super().__init__()
        self.scanner = nmap.PortScanner()
        
    def run_full_audit(self):
        return {
            'port_scan': self.scan_ports(),
            'services': self.audit_services(),
            'users': self.audit_users(),
            'network': self.audit_network(),
            'system': self.audit_system()
        }
        
    def scan_ports(self):
        results = self.scanner.scan('127.0.0.1', '1-1024')
        return results
        
    def audit_services(self):
        return [service.as_dict() for service in psutil.process_iter(['name', 'status'])]
        
    def audit_network(self):
        return {
            'connections': psutil.net_connections(),
            'interfaces': psutil.net_if_stats()
        }

    def audit_users(self):
        return {
            "users": self.get_system_users(),
            "sudo_users": self.get_sudo_users(),
            "login_history": self.get_login_history()
        }

    def get_system_users(self):
        try:
            with open('/etc/passwd', 'r') as f:
                return [line.split(':')[0] for line in f]
        except:
            return []

    def get_sudo_users(self):
        try:
            output = subprocess.check_output(['getent', 'group', 'sudo'])
            return output.decode().strip().split(':')[-1].split(',')
        except:
            return []

    def get_login_history(self):
        try:
            output = subprocess.check_output(['last', '-n', '10'])
            return output.decode().strip()
        except:
            return ""

    def audit_system(self):
        return {
            "os_version": platform.platform(),
            "security_updates": self.check_security_updates(),
            "firewall_status": self.check_firewall_status(),
            "antivirus_status": self.check_antivirus_status()
        }

    def check_security_updates(self):
        system = platform.system().lower()
        if system == 'linux':
            try:
                output = subprocess.check_output(['apt', 'list', '--upgradable'])
                return len(output.decode().split('\n')) - 2
            except:
                return "Unable to check updates"
        return "Update check not implemented for this OS"

    def check_firewall_status(self):
        system = platform.system().lower()
        if system == 'linux':
            try:
                output = subprocess.check_output(['ufw', 'status'])
                return output.decode().strip()
            except:
                return "Firewall status unknown"
        return "Firewall check not implemented for this OS"

    def check_antivirus_status(self):
        system = platform.system().lower()
        if system == 'linux':
            try:
                output = subprocess.check_output(['clamav', '--version'])
                return "ClamAV Active"
            except:
                return "No antivirus detected"
        return "Antivirus check not implemented for this OS"