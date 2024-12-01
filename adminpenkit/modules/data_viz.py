import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from modules.base_module import BaseModule

class DataVisualizer(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Data Visualizer"
        
    def create_system_usage_chart(self, frame, data):
        fig, ax = plt.subplots()
        ax.plot(data['timestamps'], data['cpu_usage'], label='CPU')
        ax.plot(data['timestamps'], data['memory_usage'], label='Memory')
        ax.set_title('System Resource Usage')
        ax.legend()
        
        canvas = FigureCanvasTkAgg(fig, frame)
        return canvas.get_tk_widget()
        
    def create_network_traffic_chart(self, frame, data):
        fig, ax = plt.subplots()
        ax.bar(data['ports'], data['connections'])
        ax.set_title('Network Traffic by Port')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        return canvas.get_tk_widget()
