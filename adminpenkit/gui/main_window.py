import tkinter as tk
from tkinter import ttk
from utils.logger import Logger
from utils.config import Config

from gui.tool_frames import (
    SystemInfoFrame,
    NetworkScanFrame,
    ServiceManagerFrame,
    SecurityCheckerFrame,
    NetworkMonitorFrame
    
)

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.logger = Logger()
        self.config = Config()
        
        # Configure main window
        self.setup_window()
        self.create_menu()
        self.create_sidebar()
        self.create_main_content()
        self.create_status_bar()

    def setup_window(self):
        self.root.configure(bg='#f0f0f0')
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Scan")
        file_menu.add_command(label="Open Report")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Scanner")
        tools_menu.add_command(label="Port Scanner")
        tools_menu.add_command(label="System Info")
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation")
        help_menu.add_command(label="About")
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def create_sidebar(self):
        sidebar = ttk.Frame(self.root, relief='raised')
        sidebar.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        
        # Tool buttons with commands
        ttk.Button(
            sidebar, 
            text="Network Tools",
            command=lambda: self.notebook.select(self.network_scan_frame)
        ).pack(pady=5, padx=5, fill=tk.X)
        
        ttk.Button(
            sidebar, 
            text="System Info",
            command=lambda: self.notebook.select(self.sys_info_frame)
        ).pack(pady=5, padx=5, fill=tk.X)
        
        ttk.Button(
            sidebar, 
            text="Security Scan",
            command=lambda: self.notebook.select(self.security_frame)
        ).pack(pady=5, padx=5, fill=tk.X)
        
        ttk.Button(
            sidebar, 
            text="Services",
            command=lambda: self.notebook.select(self.service_frame)
        ).pack(pady=5, padx=5, fill=tk.X)

    def create_main_content(self):
        self.main_content = ttk.Frame(self.root)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)
        self.create_tool_frames()

    def create_tool_frames(self):
        self.notebook = ttk.Notebook(self.main_content)
        self.notebook.pack(expand=True, fill="both")
        
        # Welcome frame
        self.welcome_frame = ttk.Frame(self.notebook)
        welcome_label = ttk.Label(
            self.welcome_frame,
            text="Welcome to AdminPenKit\nSelect a tool from the sidebar to begin",
            justify=tk.CENTER
        )
        welcome_label.pack(expand=True)
        
        # Add all frames
        self.notebook.add(self.welcome_frame, text="Welcome")
        self.sys_info_frame = SystemInfoFrame(self.notebook)
        self.network_scan_frame = NetworkScanFrame(self.notebook)
        self.service_frame = ServiceManagerFrame(self.notebook)
        self.security_frame = SecurityCheckerFrame(self.notebook)
        self.network_monitor_frame = NetworkMonitorFrame(self.notebook)
        
        self.notebook.add(self.sys_info_frame, text="System Info")
        self.notebook.add(self.network_scan_frame, text="Network Scanner")
        self.notebook.add(self.service_frame, text="Services")
        self.notebook.add(self.security_frame, text="Security")
        self.notebook.add(self.network_monitor_frame, text="Network Monitor")
        
        self.notebook.select(0)
    def create_status_bar(self):
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        
        self.status_label = ttk.Label(
            self.status_bar,
            text="Ready",
            padding=(5, 2)
        )
        self.status_label.pack(side=tk.LEFT)
        
        version_label = ttk.Label(
            self.status_bar,
            text="AdminPenKit v1.0.0",
            padding=(5, 2)
        )
        version_label.pack(side=tk.RIGHT)