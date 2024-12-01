import os
import tkinter as tk
from tkinter import ttk, filedialog
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from modules.system_info import SystemInfoModule
from modules.network_scanner import NetworkScanner
from modules.service_manager import ServiceManager
from modules.security_checker import SecurityChecker
from modules.data_viz import DataVisualizer
from modules.security_audit import SecurityAuditor
from modules.reporting import ReportGenerator



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
        
        self.scan_button = ttk.Button(input_frame, text="Scan", command=self.start_scan)
        self.scan_button.pack(side="left")
        
        # Status label
        self.status_label = ttk.Label(self, text="Ready")
        self.status_label.pack(fill="x", padx=5)
        
        # Results frame
        self.results_tree = ttk.Treeview(self, columns=("IP", "Hostname", "State"))
        self.results_tree.heading("IP", text="IP")
        self.results_tree.heading("Hostname", text="Hostname")
        self.results_tree.heading("State", text="State")
        self.results_tree.pack(expand=True, fill="both", padx=5, pady=5)
    def start_scan(self):
        target_ip = self.ip_entry.get()
        if target_ip:
            self.status_label.config(text="Scanning...")
            self.scan_button.config(state='disabled')
            try:
                results = self.scanner.scan_target(target_ip)
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
        # Control Panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # System Usage Button
        ttk.Button(control_frame, 
                  text="System Usage",
                  command=self.show_system_usage).pack(side="left", padx=5)
        
        # Network Traffic Button
        ttk.Button(control_frame, 
                  text="Network Traffic",
                  command=self.show_network_traffic).pack(side="left", padx=5)
        
        # Resource Usage Button
        ttk.Button(control_frame,
                  text="Resource Usage",
                  command=self.show_resource_usage).pack(side="left", padx=5)
        
        # Chart Display Area
        self.chart_frame = ttk.Frame(self)
        self.chart_frame.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Initialize matplotlib figure
        self.figure = Figure(figsize=(6, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, self.chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def show_system_usage(self):
        self.figure.clear()
        data = self.visualizer.get_system_usage()
        ax = self.figure.add_subplot(111)
        ax.plot(data['timestamps'], data['cpu_usage'], label='CPU')
        ax.plot(data['timestamps'], data['memory_usage'], label='Memory')
        ax.set_title('System Resource Usage')
        ax.legend()
        self.canvas.draw()
        
    def show_network_traffic(self):
        self.figure.clear()
        data = self.visualizer.get_network_traffic()
        ax = self.figure.add_subplot(111)
        ax.bar(data['interfaces'], data['bandwidth'])
        ax.set_title('Network Traffic by Interface')
        self.canvas.draw()
        
    def show_resource_usage(self):
        self.figure.clear()
        data = self.visualizer.get_resource_usage()
        ax = self.figure.add_subplot(111)
        ax.pie(data['values'], labels=data['labels'], autopct='%1.1f%%')
        ax.set_title('Resource Usage Distribution')
        self.canvas.draw()

class SecurityAuditFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.auditor = SecurityAuditor()
        self.create_widgets()

    def create_widgets(self):
        # Control Panel
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # Audit Controls
        ttk.Button(control_frame, text="Run Full Audit",
                  command=self.run_audit).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Quick Scan",
                  command=self.quick_scan).pack(side="left", padx=5)
        
        # Progress Bar
        self.progress = ttk.Progressbar(control_frame, mode='determinate')
        self.progress.pack(side="left", fill="x", expand=True, padx=5)
        
        # Status Label
        self.status_label = ttk.Label(control_frame, text="Ready")
        self.status_label.pack(side="right", padx=5)

        # Results Display
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=5, pady=5)

        # Create tabs for different audit categories
        self.system_frame = ttk.Frame(self.notebook)
        self.network_frame = ttk.Frame(self.notebook)
        self.user_frame = ttk.Frame(self.notebook)
        self.file_frame = ttk.Frame(self.notebook)

        # Initialize results trees for each category
        self.system_tree = self.create_category_tree(self.system_frame)
        self.network_tree = self.create_category_tree(self.network_frame)
        self.user_tree = self.create_category_tree(self.user_frame)
        self.file_tree = self.create_category_tree(self.file_frame)

        self.notebook.add(self.system_frame, text="System Security")
        self.notebook.add(self.network_frame, text="Network Security")
        self.notebook.add(self.user_frame, text="User Security")
        self.notebook.add(self.file_frame, text="File Security")

    def create_category_tree(self, parent):
        tree = ttk.Treeview(parent, columns=("Status", "Details"), show="headings")
        tree.heading("Status", text="Status")
        tree.heading("Details", text="Details")
        tree.pack(fill="both", expand=True)
        return tree

    def run_audit(self):
        self.status_label.config(text="Running full audit...")
        self.progress["value"] = 0
        
        results = self.auditor.run_full_audit()
        self.display_results(results)
        
        self.status_label.config(text="Audit complete")
        self.progress["value"] = 100

    def quick_scan(self):
        self.status_label.config(text="Running quick scan...")
        self.progress["value"] = 0
        
        results = self.auditor.quick_scan()
        self.display_results(results)
        
        self.status_label.config(text="Scan complete")
        self.progress["value"] = 100

    def display_results(self, results):
        # Clear previous results
        for tree in [self.system_tree, self.network_tree, 
                    self.user_tree, self.file_tree]:
            for item in tree.get_children():
                tree.delete(item)
        
        # Update each category
        self.update_category_tree(self.system_tree, results.get('system', {}))
        self.update_category_tree(self.network_tree, results.get('network', {}))
        self.update_category_tree(self.user_tree, results.get('user', {}))
        self.update_category_tree(self.file_tree, results.get('file', {}))

    def update_category_tree(self, tree, results):
        for check, data in results.items():
            status = data.get('status', 'Unknown')
            details = data.get('details', '')
            tree.insert("", "end", values=(status, details))

class ReportingFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.report_gen = ReportGenerator()
        self.create_widgets()

    def create_widgets(self):
        # Report Configuration
        config_frame = ttk.LabelFrame(self, text="Report Configuration")
        config_frame.pack(fill="x", padx=5, pady=5)

        # Report Type Selection
        type_frame = ttk.Frame(config_frame)
        type_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(type_frame, text="Report Type:").pack(side="left", padx=5)
        self.report_type = tk.StringVar(value="pdf")
        ttk.Radiobutton(type_frame, text="PDF", variable=self.report_type,
                       value="pdf").pack(side="left")
        ttk.Radiobutton(type_frame, text="JSON", variable=self.report_type,
                       value="json").pack(side="left")
        ttk.Radiobutton(type_frame, text="CSV", variable=self.report_type,
                       value="csv").pack(side="left")

        # Report Content Selection
        content_frame = ttk.Frame(config_frame)
        content_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(content_frame, text="Include:").pack(side="left", padx=5)
        self.include_system = tk.BooleanVar(value=True)
        self.include_network = tk.BooleanVar(value=True)
        self.include_security = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(content_frame, text="System Info", 
                       variable=self.include_system).pack(side="left")
        ttk.Checkbutton(content_frame, text="Network Data", 
                       variable=self.include_network).pack(side="left")
        ttk.Checkbutton(content_frame, text="Security Audit", 
                       variable=self.include_security).pack(side="left")

        # Report Options
        options_frame = ttk.Frame(config_frame)
        options_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(options_frame, text="Output Directory:").pack(side="left", padx=5)
        self.output_dir = ttk.Entry(options_frame)
        self.output_dir.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(options_frame, text="Browse", 
                  command=self.browse_output).pack(side="left")

        # Generate Button with Progress
        action_frame = ttk.Frame(self)
        action_frame.pack(fill="x", pady=10)
        
        self.progress = ttk.Progressbar(action_frame, mode='determinate')
        self.progress.pack(side="left", fill="x", expand=True, padx=5)
        
        ttk.Button(action_frame, text="Generate Report",
                  command=self.generate_report).pack(side="left", padx=5)

        # Report List
        list_frame = ttk.LabelFrame(self, text="Generated Reports")
        list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add search/filter
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(filter_frame, text="Filter:").pack(side="left")
        self.filter_entry = ttk.Entry(filter_frame)
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.filter_entry.bind('<KeyRelease>', self.filter_reports)

        # Report list with scrollbar
        self.report_list = ttk.Treeview(list_frame,
                                      columns=("Date", "Type", "Path"))
        self.report_list.heading("Date", text="Date")
        self.report_list.heading("Type", text="Type")
        self.report_list.heading("Path", text="File Path")
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", 
                                command=self.report_list.yview)
        self.report_list.configure(yscrollcommand=scrollbar.set)
        
        self.report_list.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Right-click menu
        self.create_context_menu()

    def browse_output(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir.delete(0, tk.END)
            self.output_dir.insert(0, directory)

    def generate_report(self):
        self.progress["value"] = 0
        report_config = {
            "type": self.report_type.get(),
            "include_system": self.include_system.get(),
            "include_network": self.include_network.get(),
            "include_security": self.include_security.get(),
            "output_dir": self.output_dir.get()
        }
        
        report_path = self.report_gen.generate(report_config)
        self.progress["value"] = 100
        self.update_report_list(report_path)

    def filter_reports(self, event=None):
        search_term = self.filter_entry.get().lower()
        for item in self.report_list.get_children():
            if search_term in self.report_list.item(item)['values'][2].lower():
                self.report_list.reattach(item, '', 'end')
            else:
                self.report_list.detach(item)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Open Report", 
                                    command=self.open_report)
        self.context_menu.add_command(label="Open Containing Folder", 
                                    command=self.open_folder)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete Report", 
                                    command=self.delete_report)
        
        self.report_list.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        item = self.report_list.identify_row(event.y)
        if item:
            self.report_list.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def open_report(self):
        selected = self.report_list.selection()
        if selected:
            path = self.report_list.item(selected[0])['values'][2]
            os.startfile(path)

    def open_folder(self):
        selected = self.report_list.selection()
        if selected:
            path = self.report_list.item(selected[0])['values'][2]
            os.startfile(os.path.dirname(path))

    def delete_report(self):
        selected = self.report_list.selection()
        if selected:
            path = self.report_list.item(selected[0])['values'][2]
            os.remove(path)
            self.report_list.delete(selected)
