import os
import socket
import hashlib
import platform
import subprocess
from adminpenkit.modules.base_module import BaseModule
class SecurityAuditor(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Security Auditor"
        
    def initialize(self):
        return True
        
    def execute(self):
        return self.run_full_audit()
        
    def cleanup(self):
        return True
        
    def run_full_audit(self):
        return {
            "system_security": self.audit_system_security(),
            "network_security": self.audit_network_security(),
            "user_security": self.audit_user_security(),
            "file_security": self.audit_file_security()
        }
        
    def audit_system_security(self):
        results = {
            "os_version": platform.platform(),
            "security_updates": self.check_security_updates(),
            "firewall_status": self.check_firewall_status(),
            "antivirus_status": self.check_antivirus_status()
        }
        return results

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
    def audit_network_security(self):
        results = {
            "open_ports": self.scan_open_ports(),
            "active_connections": self.check_active_connections(),
            "ssl_certificates": self.check_ssl_certificates()
        }
        return results

    def scan_open_ports(self):
        common_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432]
        open_ports = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    def check_active_connections(self):
        connections = []
        try:
            output = subprocess.check_output(['netstat', '-tuln'])
            return output.decode().strip()
        except:
            return "Unable to check connections"

    def check_ssl_certificates(self):
        ssl_info = {}
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection(("localhost", 443)) as sock:
                with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "expires": cert['notAfter']
                    }
        except:
            ssl_info = {"status": "No SSL certificates found"}
        return ssl_info        
    def audit_user_security(self):
        results = {
            "user_permissions": self.check_user_permissions(),
            "password_policy": self.check_password_policy(),
            "login_history": self.check_login_history()
        }
        return results
        
    def audit_file_security(self):
        results = {
            "sensitive_files": self.check_sensitive_files(),
            "file_permissions": self.check_file_permissions(),
            "integrity_checks": self.perform_integrity_checks()
        }
        return results
