import logging
import time
from functools import wraps

class NetworkMonitorError(Exception):
    def __init__(self, message, error_code=None, details=None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = time.time()
        
    def to_dict(self):
        return {
            'message': str(self),
            'error_code': self.error_code,
            'details': self.details,
            'timestamp': self.timestamp
        }

def handle_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {str(e)}")
            raise RuntimeError(f"Operation failed: {str(e)}")
    return wrapper
