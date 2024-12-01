import pytest
import time
from adminpenkit.modules.system_info import SystemInfoModule
from adminpenkit.modules.network_scanner import NetworkScanner
from adminpenkit.modules.security_audit import SecurityAuditor

def test_module_performance():
    modules = [
        SystemInfoModule(),
        NetworkScanner(),
        SecurityAuditor()
    ]
    
    for module in modules:
        start_time = time.time()
        module.execute()
        execution_time = time.time() - start_time
        
        assert execution_time < 5.0  # Performance threshold

def test_concurrent_operations():
    scanner = NetworkScanner()
    auditor = SecurityAuditor()
    
    # Test parallel execution
    scanner_result = scanner.execute()
    audit_result = auditor.execute()
    
    assert scanner_result is not None
    assert audit_result is not None
