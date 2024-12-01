import json
import csv
from datetime import datetime
import platform

class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.now()
        
    def generate_report(self, data, format='html'):
        report = {
            'timestamp': self.timestamp.isoformat(),
            'system': platform.uname()._asdict(),
            'audit_results': data
        }
        
        if format == 'json':
            return self.to_json(report)
        elif format == 'html':
            return self.to_html(report)
        elif format == 'csv':
            return self.to_csv(report)
