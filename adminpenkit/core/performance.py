from functools import lru_cache
import time

def measure_execution_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        execution_time = time.time() - start_time
        print(f"{func.__name__} executed in {execution_time:.2f} seconds")
        return result
    return wrapper

@lru_cache(maxsize=128)
def cached_operation(operation_key):
    return f"Cached result for {operation_key}"
