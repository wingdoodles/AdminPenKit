import os
import socket
import hashlib
import platform
import subprocess
import psutil
import concurrent.futures
from adminpenkit.modules.base_module import BaseModule
from functools import partial
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from adminpenkit.core.performance import measure_execution_time, cached_operation

class SecurityAuditor(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Security Auditor"
        self.timeout = 2
        self.scan_paths = ['/etc', '/usr/bin', '/usr/sbin', '/var/log']
    def quick_system_check(self):
        return {"os": platform.system(), "version": platform.version()}

    def quick_network_check(self):
        return {"connections": len(psutil.net_connections(kind='inet'))}

    def quick_user_check(self):
        return {"users": len(psutil.users())}

    def quick_file_check(self):
        return {"writable_paths": sum(1 for p in self.scan_paths if os.access(p, os.W_OK))}

    @measure_execution_time
    def execute(self):
        tasks = {
            "system": self.quick_system_check,
            "network": self.quick_network_check,
            "users": self.quick_user_check,
            "files": self.quick_file_check
        }
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(func): name for name, func in tasks.items()}
            results = {}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                results[name] = future.result()
                print(f"[{len(results)*25}%] Checked {name}")

        return results    
    def initialize(self):
        return True
        
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
        return {
            "open_ports": self.scan_open_ports(),
            "active_connections": self.check_active_connections(),
            "ssl_certificates": self.check_ssl_certificates()
        }

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
        try:
            output = subprocess.check_output(['netstat', '-tuln'])
            return output.decode().strip()
        except:
            return []

    def check_ssl_certificates(self):
        try:
            output = subprocess.check_output(['openssl', 'version'])
            return {"openssl_version": output.decode().strip()}
        except:
            return {"openssl_version": "Not available"}

    def audit_user_security(self):
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

    def audit_file_security(self):
        return {
            "world_writable": self.find_world_writable(),
            "suid_files": self.find_suid_files(),
            "sensitive_files": self.check_sensitive_files()
        }

    def find_world_writable(self):
        try:
            output = subprocess.check_output(['find', '/', '-perm', '-2', '-type', 'f'])
            return output.decode().strip().split('\n')
        except:
            return []

    def find_suid_files(self):
        try:
            output = subprocess.check_output(['find', '/', '-perm', '-4000'])
            return output.decode().strip().split('\n')
        except:
            return []

    def check_sensitive_files(self):
        sensitive_paths = ['/etc/shadow', '/etc/passwd', '/etc/sudoers']
        results = {}
        for path in sensitive_paths:
            try:
                stats = os.stat(path)
                results[path] = {
                    "permissions": oct(stats.st_mode)[-3:],
                    "owner": stats.st_uid,
                    "group": stats.st_gid
                }
            except:
                results[path] = "Not accessible"
        return results

    def scan_ports(self, ports):
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
