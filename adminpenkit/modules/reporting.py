import json
import csv
from datetime import datetime
from modules.base_module import BaseModule

class ReportingSystem(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Reporting System"
        
    def generate_report(self, data, format="pdf"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.{format}"
        
        if format == "pdf":
            return self.generate_pdf_report(data, filename)
        elif format == "json":
            return self.generate_json_report(data, filename)
        elif format == "csv":
            return self.generate_csv_report(data, filename)
