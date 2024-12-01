from abc import ABC, abstractmethod

class BaseModule(ABC):
    def __init__(self):
        self.name = self.__class__.__name__
        self.description = "Base module interface"
        self.version = "1.0"
        
    @abstractmethod
    def initialize(self):
        pass
        
    @abstractmethod
    def execute(self):
        pass
        
    @abstractmethod
    def cleanup(self):
        pass
