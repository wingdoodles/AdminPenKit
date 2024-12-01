import unittest
import platform
import sys

class PlatformCompatibilityTest(unittest.TestCase):
    def test_system_compatibility(self):
        system = platform.system().lower()
        
        if system == 'linux':
            self.test_linux_compatibility()
        elif system == 'windows':
            self.test_windows_compatibility()
        elif system == 'darwin':
            self.test_macos_compatibility()
            
    def test_module_availability(self):
        required_modules = ['psutil', 'nmap', 'tkinter']
        for module in required_modules:
            self.assertTrue(module in sys.modules)
