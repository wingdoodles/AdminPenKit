import json
import os

class Config:
    def __init__(self):
        self.config_file = "config.json"
        self.default_config = {
            "theme": "default",
            "log_level": "INFO",
            "max_threads": 5,
            "scan_timeout": 30,
            "save_reports": True
        }
        self.config = self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return self.default_config
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def get(self, key):
        return self.config.get(key, self.default_config.get(key))
    
    def set(self, key, value):
        self.config[key] = value
        self.save_config()
