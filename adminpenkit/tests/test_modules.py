import unittest
from modules.system_info import SystemInfoModule
from modules.network_scanner import NetworkScanner
from modules.service_manager import ServiceManager

class TestSystemInfo(unittest.TestCase):
    def setUp(self):
        self.sys_info = SystemInfoModule()
        
    def test_system_info_collection(self):
        info = self.sys_info.get_system_info()
        self.assertIsInstance(info, dict)
        self.assertIn("OS", info)
        self.assertIn("CPU Cores", info)
        self.assertIn("RAM Total", info)
        
    def test_disk_info(self):
        disk_info = self.sys_info.get_disk_info()
        self.assertIsInstance(disk_info, dict)
        # At least one disk should be present
        self.assertGreater(len(disk_info), 0)

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NetworkScanner()
        
    def test_scanner_initialization(self):
        self.assertIsNotNone(self.scanner)
        self.assertEqual(self.scanner.name, "Network Scanner")
        
    def test_localhost_scan(self):
        results = self.scanner.scan_network("127.0.0.1", "80")
        self.assertIsInstance(results, list)

class TestServiceManager(unittest.TestCase):
    def setUp(self):
        self.service_mgr = ServiceManager()
        
    def test_service_list(self):
        services = self.service_mgr.list_services()
        self.assertIsInstance(services, list)
