import time
import psutil
import logging
from functools import wraps

def measure_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        result = func(*args, **kwargs)
        
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss
        
        execution_time = end_time - start_time
        memory_used = end_memory - start_memory
        
        logging.info(f"Performance: {func.__name__} - Time: {execution_time:.2f}s, Memory: {memory_used/1024:.2f}KB")
        return result
    return wrapper
