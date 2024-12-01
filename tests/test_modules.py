import pytest
from adminpenkit.modules.system_info import SystemInfoModule
from adminpenkit.modules.network_scanner import NetworkScanner
from adminpenkit.modules.security_audit import SecurityAuditor


def test_system_info():
    sys_info = SystemInfoModule()
    result = sys_info.execute()
    assert result is not None
    
def test_network_scanner():
    scanner = NetworkScanner()
    result = scanner.execute()
    assert result is not None
    
def test_security_audit():
    auditor = SecurityAuditor()
    result = auditor.execute()
    assert result is not None
