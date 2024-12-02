import psutil
import platform
import subprocess
from modules.base_module import BaseModule

class ServiceManager(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Service Manager"
        self.os_type = platform.system().lower()
        
    def initialize(self):
        return True
        
    def execute(self):
        return self.list_services()
        
    def cleanup(self):
        return True
        
    def list_services(self):
        services = []
        if self.os_type == 'windows':
            for service in psutil.win_service_iter():
                try:
                    service_info = service.as_dict()
                    services.append({
                        "name": service_info["name"],
                        "display_name": service_info["display_name"],
                        "status": service_info["status"],
                        "start_type": service_info["start_type"]
                    })
                except:
                    continue
        else:
            # Linux/MacOS service handling
            try:
                output = subprocess.check_output(['systemctl', 'list-units', '--type=service', '--all'])
                for line in output.decode().split('\n')[1:-7]:
                    if line.strip():
                        parts = line.split()
                        services.append({
                            "name": parts[0],
                            "status": parts[3],
                            "description": ' '.join(parts[4:])
                        })
            except:
                pass
        return services
    
    def get_service_status(self, service_name):
        try:
            service = psutil.win_service_get(service_name)
            return service.status()
        except Exception as e:
            raise Exception(f"Failed to get service status: {str(e)}")

def start_service(self, service_name):
    if self.os_type == 'windows':
        try:
            service = psutil.win_service_get(service_name)
            return service.start()
        except Exception as e:
            raise Exception(f"Failed to start service: {str(e)}")
    else:
        subprocess.run(['systemctl', 'start', service_name])
        return True

def stop_service(self, service_name):
    if self.os_type == 'windows':
        try:
            service = psutil.win_service_get(service_name)
            return service.stop()
        except Exception as e:
            raise Exception(f"Failed to stop service: {str(e)}")
    else:
        subprocess.run(['systemctl', 'stop', service_name])
        return True

def get_service_config(self, service_name):
    if self.os_type == 'windows':
        service = psutil.win_service_get(service_name)
        config = service.as_dict()
        return {
            'start_type': config['start_type'],
            'binpath': config['binpath'],
            'username': config['username'],
            'display_name': config['display_name']
        }
    else:
        output = subprocess.check_output(['systemctl', 'show', service_name])
        config = {}
        for line in output.decode().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                config[key] = value
        return config

def set_service_config(self, service_name, config_dict):
    if self.os_type == 'windows':
        # Windows service configuration
        cmd = ['sc', 'config', service_name]
        for key, value in config_dict.items():
            cmd.extend([key, value])
        subprocess.run(cmd)
    else:
        # Linux service configuration
        service_file = f"/etc/systemd/system/{service_name}.service"
        with open(service_file, 'w') as f:
            for key, value in config_dict.items():
                f.write(f"{key}={value}\n")
        subprocess.run(['systemctl', 'daemon-reload'])
