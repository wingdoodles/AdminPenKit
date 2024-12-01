import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from modules.network_scanner import NetworkInterfaceMonitor

import time

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
