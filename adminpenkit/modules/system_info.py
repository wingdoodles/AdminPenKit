import psutil
import platform
import os
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from modules.base_module import BaseModule
from core.performance import measure_execution_time

class SystemInfoModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "System Information"
        self._cache = {}
        self.update_interval = 1000  # milliseconds

    def initialize(self):
        """Initialize the system information module"""
        return True

    @measure_execution_time
    def execute(self):
        return self.get_system_info()

    def cleanup(self):
        """Cleanup any resources"""
        return True

    def get_system_info(self):
        return {
            'hardware': self.get_hardware_info(),
            'os': self.get_os_info(),
            'performance': self.get_real_time_metrics()
        }

    @lru_cache(maxsize=32)
    def get_hardware_info(self):
        return {
            'cpu': {
                'cores': psutil.cpu_count(),
                'physical_cores': psutil.cpu_count(logical=False),
                'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
                'stats': psutil.cpu_stats()._asdict()
            },
            'memory': {
                'total': self.format_bytes(psutil.virtual_memory().total),
                'available': self.format_bytes(psutil.virtual_memory().available),
                'used': self.format_bytes(psutil.virtual_memory().used)
            },
            'disks': self.get_disk_info(),
            'network': self.get_network_info()
        }

    @lru_cache(maxsize=32)
    def get_os_info(self):
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version()
        }

    def get_real_time_metrics(self):
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters()._asdict(),
            'swap_memory': psutil.swap_memory().percent
        }

    def get_disk_info(self):
        disks = {}
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks[partition.device] = {
                    'mountpoint': partition.mountpoint,
                    'filesystem': partition.fstype,
                    'total': self.format_bytes(usage.total),
                    'used': self.format_bytes(usage.used),
                    'free': self.format_bytes(usage.free),
                    'percent': usage.percent
                }
            except Exception:
                continue
        return disks

    def get_network_info(self):
        interfaces = {}
        for name, stats in psutil.net_if_stats().items():
            interfaces[name] = {
                'status': 'Up' if stats.isup else 'Down',
                'speed': f"{stats.speed}Mb/s",
                'mtu': stats.mtu
            }
        return interfaces

    def format_bytes(self, bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.2f}{unit}"
            bytes /= 1024
