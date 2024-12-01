import tkinter as tk
from tkinter import ttk
from modules.system_info import SystemInfoModule
from modules.network_scanner import NetworkScanner
from modules.service_manager import ServiceManager
from modules.security_checker import SecurityChecker
from modules.data_viz import DataVisualizer
from modules.security_audit import SecurityAuditor


class SystemInfoFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.sys_info = SystemInfoModule()
        self.create_widgets()
        
    def create_widgets(self):
        # Create treeview for system information
        self.tree = ttk.Treeview(self, columns=("Value",), show="tree headings")
        self.tree.heading("Value", text="Value")
        self.tree.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Add refresh button
        ttk.Button(self, text="Refresh", command=self.update_info).pack(pady=5)
        
        self.update_info()
        
    def update_info(self):
        self.tree.delete(*self.tree.get_children())
        info = self.sys_info.get_system_info()
        for key, value in info.items():
            if isinstance(value, dict):
                parent = self.tree.insert("", "end", text=key)
                for sub_key, sub_value in value.items():
                    self.tree.insert(parent, "end", values=(f"{sub_key}: {sub_value}",))
            else:
                self.tree.insert("", "end", values=(f"{key}: {value}",))

class NetworkScanFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.scanner = NetworkScanner()
        self.create_widgets()
        
    def create_widgets(self):
        # Input frame
        input_frame = ttk.Frame(self)
        input_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(input_frame, text="Target IP:").pack(side="left")
        self.ip_entry = ttk.Entry(input_frame)
        self.ip_entry.pack(side="left", padx=5)
        
        ttk.Button(input_frame, text="Scan", command=self.start_scan).pack(side="left")
        
        # Results frame
        self.results_tree = ttk.Treeview(self, columns=("IP", "Hostname", "State"))
        self.results_tree.heading("IP", text="IP")
        self.results_tree.heading("Hostname", text="Hostname")
        self.results_tree.heading("State", text="State")
        self.results_tree.pack(expand=True, fill="both", padx=5, pady=5)
        
    def start_scan(self):
        target_ip = self.ip_entry.get()
        if target_ip:
            # Show scanning status
            self.status_label.config(text="Scanning...")
            self.scan_button.config(state='disabled')
            
            try:
                results = self.scanner.scan_network(target_ip)
                self.update_results(results)
            finally:
                self.status_label.config(text="Scan complete")
                self.scan_button.config(state='normal')
            
    def update_results(self, results):
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Add new results
        for host in results:
            self.results_tree.insert("", "end", values=(
                host["ip"],
                host["hostname"],
                host["state"]
            ))

class ServiceManagerFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.service_mgr = ServiceManager()
        self.create_widgets()
        
    def create_widgets(self):
        # Controls
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(control_frame, text="Refresh", command=self.refresh_services).pack(side="left", padx=5)
        
        # Service list
        self.tree = ttk.Treeview(self, columns=("Name", "Status", "Description"))
        self.tree.heading("Name", text="Service Name")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Description", text="Description")
        self.tree.pack(expand=True, fill="both", padx=5, pady=5)
        
        self.refresh_services()
        
    def refresh_services(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        services = self.service_mgr.list_services()
        for service in services:
            self.tree.insert("", "end", values=(
                service.get("name", ""),
                service.get("status", ""),
                service.get("description", "")
            ))

class SecurityCheckerFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.security_checker = SecurityChecker()
        self.create_widgets()
        
    def create_widgets(self):
        # Controls
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(control_frame, text="Run Security Check", command=self.run_checks).pack(side="left", padx=5)
        
        # Results
        self.results_text = tk.Text(self, height=20, width=60)
        self.results_text.pack(expand=True, fill="both", padx=5, pady=5)
        
    def run_checks(self):
        self.results_text.delete(1.0, tk.END)
        results = self.security_checker.run_security_checks()
        
        self.results_text.insert(tk.END, "Security Check Results:\n\n")
        for category, data in results.items():
            self.results_text.insert(tk.END, f"{category.upper()}:\n")
            self.results_text.insert(tk.END, f"{data}\n\n")

class DataVisualizationFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.visualizer = DataVisualizer()
        self.create_widgets()
        
    def create_widgets(self):
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(control_frame, text="System Usage", 
                  command=self.show_system_usage).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Network Traffic", 
                  command=self.show_network_traffic).pack(side="left", padx=5)
        
        self.chart_frame = ttk.Frame(self)
        self.chart_frame.pack(expand=True, fill="both", padx=5, pady=5)

class SecurityAuditFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.auditor = SecurityAuditor()
        self.create_widgets()
        
    def create_widgets(self):
        # Control Panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(control_frame, text="Run Full Audit", 
                  command=self.run_audit).pack(side="left", padx=5)
        
        # Results Display
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Create tabs for different audit categories
        self.system_frame = ttk.Frame(self.notebook)
        self.network_frame = ttk.Frame(self.notebook)
        self.user_frame = ttk.Frame(self.notebook)
        self.file_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.system_frame, text="System Security")
        self.notebook.add(self.network_frame, text="Network Security")
        self.notebook.add(self.user_frame, text="User Security")
        self.notebook.add(self.file_frame, text="File Security")
        
    def run_audit(self):
        results = self.auditor.run_full_audit()
        self.display_results(results)
