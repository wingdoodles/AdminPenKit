import os
import socket
import hashlib
import platform
from modules.base_module import BaseModule

class SecurityAuditor(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Security Auditor"
        
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
        
    def audit_network_security(self):
        results = {
            "open_ports": self.scan_open_ports(),
            "active_connections": self.check_active_connections(),
            "ssl_certificates": self.check_ssl_certificates()
        }
        return results
        
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
