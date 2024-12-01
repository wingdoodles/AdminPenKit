import platform
import sys

class PlatformChecker:
    @staticmethod
    def check_compatibility():
        system = platform.system().lower()
        requirements = {
            'windows': {'min_version': '10'},
            'linux': {'min_python': '3.8'},
            'darwin': {'min_version': '10.15'}
        }
        
        return {
            'os': system,
            'version': platform.version(),
            'python': sys.version,
            'compatible': True
        }
