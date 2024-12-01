import platform
import psutil
import socket
from adminpenkit.modules.base_module import BaseModule

class SystemInfoModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "System Information"
        self.description = "Collects and displays system information"
        
    def initialize(self):
        """Initialize the system information module"""
        return True
        
    def execute(self):
        """Execute system information gathering"""
        return self.get_system_info()
        
    def cleanup(self):
        """Cleanup any resources"""
        return True
        
    def get_system_info(self):
        return {
            "OS": platform.system(),
            "OS Version": platform.version(),
            "Architecture": platform.machine(),
            "Processor": platform.processor(),
            "Hostname": socket.gethostname(),
            "CPU Cores": psutil.cpu_count(),
            "RAM Total": f"{round(psutil.virtual_memory().total / (1024.0 ** 3), 2)} GB",
            "RAM Available": f"{round(psutil.virtual_memory().available / (1024.0 ** 3), 2)} GB",
            "Disk Usage": self.get_disk_info()
        }
    
    def get_disk_info(self):
        disks = {}
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks[partition.mountpoint] = {
                    "Total": f"{usage.total / (1024.0 ** 3):.2f} GB",
                    "Used": f"{usage.used / (1024.0 ** 3):.2f} GB",
                    "Free": f"{usage.free / (1024.0 ** 3):.2f} GB"
                }
            except:
                continue
        return disks
