import tkinter as tk
from tkinter import ttk

class ProgressFrame(ttk.Frame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        
        self.progress = ttk.Progressbar(
            self,
            orient="horizontal",
            length=200,
            mode="determinate"
        )
        self.progress.pack(pady=5)
        
        self.status_label = ttk.Label(self, text="")
        self.status_label.pack()
        
    def update_progress(self, value, status_text=""):
        self.progress["value"] = value
        self.status_label["text"] = status_text
