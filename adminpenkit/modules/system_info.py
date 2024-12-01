import psutil
import platform
import os
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from modules.base_module import BaseModule
from core.performance import measure_execution_time
class SystemInfoModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "System Information"

    def initialize(self):
        """Initialize the system information module"""
        return True

    @measure_execution_time
    def execute(self):
        tasks = {
            "hardware": self.get_hardware_info,
            "os": self.get_os_info,
            "cpu": self.get_cpu_info,
            "memory": self.get_memory_info
        }
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(func): name for name, func in tasks.items()}
            results = {}
            for future in futures.as_completed(futures):
                name = futures[future]
                results[name] = future.result()
        return results

    def cleanup(self):
        """Cleanup any resources"""
        return True

    @lru_cache(maxsize=32)
    def get_hardware_info(self):
        # Hardware info implementation
        return {"platform": platform.machine(), "processor": platform.processor()}

    @lru_cache(maxsize=32)
    def get_os_info(self):
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version()
        }

    @lru_cache(maxsize=32)
    def get_cpu_info(self):
        return {
            "cpu_count": psutil.cpu_count(),
            "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
            "cpu_percent": psutil.cpu_percent(interval=0.1)
        }
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

    @lru_cache(maxsize=32)
    def get_memory_info(self):
        mem = psutil.virtual_memory()
        return {
            "total": mem.total,
            "available": mem.available,
            "percent": mem.percent,
            "used": mem.used,
            "free": mem.free
        }
