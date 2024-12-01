import json
import csv
import os
from datetime import datetime
from fpdf import FPDF
from modules.base_module import BaseModule

class ReportGenerator(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Report Generator"
        self.report_dir = "reports"
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            
    def generate_report(self, data, report_type="pdf"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}"
        
        if report_type == "pdf":
            return self.generate_pdf(data, filename)
        elif report_type == "json":
            return self.generate_json(data, filename)
        elif report_type == "csv":
            return self.generate_csv(data, filename)
            
    def generate_pdf(self, data, filename):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Add report content
        pdf.cell(200, 10, txt="AdminPenKit Security Report", ln=1, align='C')
        
        for section, content in data.items():
            pdf.cell(200, 10, txt=f"\n{section}", ln=1, align='L')
            for key, value in content.items():
                pdf.cell(200, 10, txt=f"{key}: {value}", ln=1, align='L')
                
        filepath = os.path.join(self.report_dir, f"{filename}.pdf")
        pdf.output(filepath)
        return filepath