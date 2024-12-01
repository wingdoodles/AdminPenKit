import os
import time

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
from modules.network_scanner import NetworkInterfaceMonitor


class SystemInfoFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.sys_info = SystemInfoModule()
        self.monitoring_active = False
        self.create_widgets()
        self.notebook.bind('<<NotebookTabChanged>>', self.handle_tab_change)

    def create_widgets(self):
        # Create main notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=5, pady=5)

        # Hardware Info Tab
        self.hw_frame = ttk.Frame(self.notebook)
        self.create_hardware_view()
        self.notebook.add(self.hw_frame, text="Hardware")

        # Real-time Monitoring Tab
        self.monitor_frame = ttk.Frame(self.notebook)
        self.create_monitoring_widgets()
        self.notebook.add(self.monitor_frame, text="Monitoring")

        # Refresh button
        ttk.Button(self, text="Refresh", command=self.update_info).pack(pady=5)


    def create_hardware_view(self):
        self.hw_tree = ttk.Treeview(self.hw_frame, columns=('Property', 'Value'), show='tree headings')
        self.hw_tree.heading('Property', text='Property')
        self.hw_tree.heading('Value', text='Value')
        self.hw_tree.column('Property', width=150)
        self.hw_tree.column('Value', width=250)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(self.hw_frame, orient="vertical", command=self.hw_tree.yview)
        hsb = ttk.Scrollbar(self.hw_frame, orient="horizontal", command=self.hw_tree.xview)
        self.hw_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.hw_tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')
        
        self.hw_frame.grid_columnconfigure(0, weight=1)
        self.hw_frame.grid_rowconfigure(0, weight=1)

    def create_monitoring_widgets(self):
        # Frame for monitoring controls
        control_frame = ttk.Frame(self.monitor_frame)
        control_frame.pack(fill='x', pady=5)
        
        # CPU Usage
        ttk.Label(self.monitor_frame, text="CPU Usage:").pack(pady=5)
        self.cpu_frame = ttk.Frame(self.monitor_frame)
        self.cpu_frame.pack(pady=5)
        self.cpu_progress = ttk.Progressbar(self.cpu_frame, length=200, mode='determinate')
        self.cpu_progress.pack(side='left', padx=5)
        self.cpu_label = ttk.Label(self.cpu_frame, text="0%")
        self.cpu_label.pack(side='left')

        # Memory Usage
        ttk.Label(self.monitor_frame, text="Memory Usage:").pack(pady=5)
        self.mem_frame = ttk.Frame(self.monitor_frame)
        self.mem_frame.pack(pady=5)
        self.mem_progress = ttk.Progressbar(self.mem_frame, length=200, mode='determinate')
        self.mem_progress.pack(side='left', padx=5)
        self.mem_label = ttk.Label(self.mem_frame, text="0%")
        self.mem_label.pack(side='left')

        # Disk Usage
        ttk.Label(self.monitor_frame, text="Disk Usage:").pack(pady=5)
        self.disk_frame = ttk.Frame(self.monitor_frame)
        self.disk_frame.pack(pady=5)
        self.disk_progress = ttk.Progressbar(self.disk_frame, length=200, mode='determinate')
        self.disk_progress.pack(side='left', padx=5)
        self.disk_label = ttk.Label(self.disk_frame, text="0%")
        self.disk_label.pack(side='left')

    def handle_tab_change(self, event):
        current_tab = self.notebook.select()
        is_monitoring_tab = current_tab == str(self.monitor_frame)
        
        if is_monitoring_tab and not self.monitoring_active:
            self.start_monitoring()
        elif not is_monitoring_tab and self.monitoring_active:
            self.stop_monitoring()

    def start_monitoring(self):
        self.monitoring_active = True
        self.update_metrics()
        print("Monitoring started")  # Debug line

    def stop_monitoring(self):
        self.monitoring_active = False
        print("Monitoring stopped")  # Debug line

    def update_metrics(self):
        if not self.monitoring_active:
            return
            
        metrics = self.sys_info.get_real_time_metrics()
        
        # Update CPU
        self.cpu_progress['value'] = metrics['cpu_percent']
        self.cpu_label.config(text=f"{metrics['cpu_percent']:.1f}%")
        
        # Update Memory
        self.mem_progress['value'] = metrics['memory_usage']
        self.mem_label.config(text=f"{metrics['memory_usage']:.1f}%")
        
        # Update Disk
        self.disk_progress['value'] = metrics['disk_usage']
        self.disk_label.config(text=f"{metrics['disk_usage']:.1f}%")
        
        if self.monitoring_active:
            self.after(1000, self.update_metrics)

    def update_info(self):
        system_info = self.sys_info.get_system_info()
        self.info_tree.delete(*self.info_tree.get_children())
        for category, info in system_info.items():
            category_id = self.info_tree.insert('', 'end', values=(category, ''))
            for key, value in info.items():
                self.info_tree.insert(category_id, 'end', values=(key, value))

    def update_hardware_tree(self, hardware_info):
        self.hw_tree.delete(*self.hw_tree.get_children())
        for category, data in hardware_info.items():
            parent = self.hw_tree.insert("", "end", text=category)
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        sub_parent = self.hw_tree.insert(parent, "end", text=key)
                        for sub_key, sub_value in value.items():
                            self.hw_tree.insert(sub_parent, "end", 
                                              values=(sub_key, sub_value))
                    else:
                        self.hw_tree.insert(parent, "end", 
                                          values=(key, value))
                                            
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

def create_treeview(self, parent):
    tree = ttk.Treeview(parent, columns=('Property', 'Value'), show='tree headings')
    tree.heading('Property', text='Property')
    tree.heading('Value', text='Value')
    tree.column('Property', width=150)
    tree.column('Value', width=250)
    tree.pack(fill='both', expand=True)
    
    # Add scrollbars
    vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    
    # Grid layout
    tree.grid(column=0, row=0, sticky='nsew')
    vsb.grid(column=1, row=0, sticky='ns')
    hsb.grid(column=0, row=1, sticky='ew')
    
    parent.grid_columnconfigure(0, weight=1)
    parent.grid_rowconfigure(0, weight=1)
    
    return tree

def create_interface_widgets(self):
    # Interface Selection
    self.interface_frame = ttk.LabelFrame(self, text="Network Interfaces")
    self.interface_frame.pack(fill='x', padx=5, pady=5)
    
    self.interface_var = tk.StringVar()
    self.interface_combo = ttk.Combobox(
        self.interface_frame, 
        textvariable=self.interface_var,
        values=self.network_monitor.get_network_interfaces()
    )
    self.interface_combo.pack(padx=5, pady=5)
    self.interface_combo.bind('<<ComboboxSelected>>', self.update_interface_info)
    
    # Interface Details
    self.details_notebook = ttk.Notebook(self)
    self.details_notebook.pack(fill='both', expand=True, padx=5, pady=5)
    
    # Status Tab
    self.status_frame = ttk.Frame(self.details_notebook)
    self.details_notebook.add(self.status_frame, text="Status")
    
    # Configuration Tab
    self.config_frame = ttk.Frame(self.details_notebook)
    self.details_notebook.add(self.config_frame, text="Configuration")
    
    # Statistics Tab
    self.stats_frame = ttk.Frame(self.details_notebook)
    self.details_notebook.add(self.stats_frame, text="Statistics")
    
    # Traffic Graph
    self.graph_frame = ttk.Frame(self.details_notebook)
    self.details_notebook.add(self.graph_frame, text="Traffic")
    self.create_traffic_graph()
    
    # Start monitoring
    self.start_interface_monitoring()

def create_traffic_graph(self):
    self.figure = Figure(figsize=(6, 4), dpi=100)
    self.plot = self.figure.add_subplot(111)
    self.canvas = FigureCanvasTkAgg(self.figure, master=self.graph_frame)
    self.canvas.draw()
    self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

class NetworkMonitorFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.network_monitor = NetworkInterfaceMonitor()
        self.traffic_data = {'time': [], 'rx': [], 'tx': []}
        self.create_widgets()
        self.start_monitoring()

    def create_widgets(self):
        # Main container with tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Interface Selection Panel
        self.create_interface_panel()
        
        # Status Monitor Tab
        self.status_frame = ttk.Frame(self.notebook)
        self.create_status_widgets()
        self.notebook.add(self.status_frame, text="Status")

        # Statistics Tab
        self.stats_frame = ttk.Frame(self.notebook)
        self.create_statistics_widgets()
        self.notebook.add(self.stats_frame, text="Statistics")

        # Traffic Graph Tab
        self.traffic_frame = ttk.Frame(self.notebook)
        self.create_traffic_graph()
        self.notebook.add(self.traffic_frame, text="Traffic")

        # Active Connections Tab
        self.connections_frame = ttk.Frame(self.notebook)
        self.create_connections_widgets()
        self.notebook.add(self.connections_frame, text="Connections")

    def create_interface_panel(self):
        panel = ttk.LabelFrame(self, text="Interface Selection")
        panel.pack(fill='x', padx=5, pady=5)

        self.interface_var = tk.StringVar()
        interfaces = self.network_monitor.get_network_interfaces()
        self.interface_combo = ttk.Combobox(
            panel, 
            textvariable=self.interface_var,
            values=interfaces
        )
        self.interface_combo.pack(padx=5, pady=5)
        self.interface_combo.bind('<<ComboboxSelected>>', self.on_interface_change)

    def create_status_widgets(self):
        # Interface Status
        self.status_tree = ttk.Treeview(self.status_frame, columns=('Property', 'Value'), show='headings')
        self.status_tree.heading('Property', text='Property')
        self.status_tree.heading('Value', text='Value')
        self.status_tree.pack(fill='both', expand=True, padx=5, pady=5)

    def create_statistics_widgets(self):
        # Network Statistics
        self.stats_tree = ttk.Treeview(self.stats_frame, columns=('Metric', 'Value'), show='headings')
        self.stats_tree.heading('Metric', text='Metric')
        self.stats_tree.heading('Value', text='Value')
        self.stats_tree.pack(fill='both', expand=True, padx=5, pady=5)

    def create_traffic_graph(self):
        self.figure = Figure(figsize=(6, 4), dpi=100)
        self.plot = self.figure.add_subplot(111)
        self.plot.set_title('Network Traffic')
        self.plot.set_xlabel('Time')
        self.plot.set_ylabel('Bytes/s')
        
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.traffic_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

    def create_connections_widgets(self):
        # Active Connections
        self.connections_tree = ttk.Treeview(
            self.connections_frame, 
            columns=('Local', 'Remote', 'Status', 'PID'),
            show='headings'
        )
        self.connections_tree.heading('Local', text='Local Address')
        self.connections_tree.heading('Remote', text='Remote Address')
        self.connections_tree.heading('Status', text='Status')
        self.connections_tree.heading('PID', text='PID')
        self.connections_tree.pack(fill='both', expand=True, padx=5, pady=5)

    def start_monitoring(self):
        self.update_interface_info()
        self.update_traffic_graph()
        self.after(1000, self.start_monitoring)

    def update_interface_info(self):
        if self.interface_var.get():
            interface = self.interface_var.get()
            details = self.network_monitor.get_interface_details()[interface]
            
            # Update Status
            self.status_tree.delete(*self.status_tree.get_children())
            for key, value in details['status'].items():
                self.status_tree.insert('', 'end', values=(key, value))
            
            # Update Statistics
            self.stats_tree.delete(*self.stats_tree.get_children())
            for key, value in details['statistics'].items():
                self.stats_tree.insert('', 'end', values=(key, self.format_bytes(value)))
            
            # Update Connections
            self.update_connections(interface)
        
    def on_interface_change(self, event):
        """Handle interface selection change"""
        selected_interface = self.interface_combo.get()
        # Update network statistics for the selected interface
        interface_stats = self.network_monitor.monitor_interfaces()
        
        # Update the interface display
        self.update_interface_stats(interface_stats)
        
    def update_interface_stats(self, stats):
        """Update the interface statistics display"""
        if hasattr(self, 'stats_tree'):
            self.stats_tree.delete(*self.stats_tree.get_children())
            for interface, data in stats['interfaces'].items():
                self.stats_tree.insert('', 'end', values=(interface, data))

    def update_traffic_graph(self):
        if self.interface_var.get():
            interface = self.interface_var.get()
            bandwidth = self.network_monitor.get_bandwidth_usage(interface)
            
            current_time = time.strftime('%H:%M:%S')
            self.traffic_data['time'].append(current_time)
            self.traffic_data['rx'].append(bandwidth['bytes_recv_per_sec'])
            self.traffic_data['tx'].append(bandwidth['bytes_sent_per_sec'])
            
            # Keep last 60 seconds of data
            if len(self.traffic_data['time']) > 60:
                self.traffic_data['time'].pop(0)
                self.traffic_data['rx'].pop(0)
                self.traffic_data['tx'].pop(0)
            
            self.plot.clear()
            self.plot.plot(self.traffic_data['rx'], label='RX')
            self.plot.plot(self.traffic_data['tx'], label='TX')
            self.plot.legend()
            self.canvas.draw()

    def update_connections(self, interface):
        self.connections_tree.delete(*self.connections_tree.get_children())
        connections = self.network_monitor.get_active_connections(interface)
        for conn in connections:
            self.connections_tree.insert('', 'end', values=(
                conn['local_address'],
                conn['remote_address'],
                conn['status'],
                conn['pid']
            ))

    def format_bytes(self, bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
