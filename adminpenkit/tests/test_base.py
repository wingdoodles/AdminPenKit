import unittest
from utils.logger import Logger
from utils.config import Config

class BaseTest(unittest.TestCase):
    def setUp(self):
        self.logger = Logger()
        self.config = Config()
        
    def tearDown(self):
        pass
