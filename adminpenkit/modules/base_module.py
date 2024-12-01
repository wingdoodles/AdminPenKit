from abc import ABC, abstractmethod
from adminpenkit.utils.error_handler import handle_errors
from adminpenkit.utils.performance import measure_performance
class BaseModule(ABC):
    def __init__(self):
        self.name = self.__class__.__name__
        self.description = "Base module interface"
        self.version = "1.0"
        
    @abstractmethod
    @handle_errors
    @measure_performance
    def initialize(self):
        pass
        
    @abstractmethod
    @handle_errors
    @measure_performance
    def execute(self):
        pass
        
    @abstractmethod
    @handle_errors
    @measure_performance
    def cleanup(self):
        pass
