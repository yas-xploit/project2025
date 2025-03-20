import tkinter as tk
from tkinter import ttk, scrolledtext
import logging
from utils import TextHandler

class LogsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()
    def create_widgets(self):
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(filter_frame, text="Filter Logs:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.filter_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        self.log_text = scrolledtext.ScrolledText(self, state='disabled', width=100, height=20)
        self.log_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.text_handler = TextHandler(self.log_text)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.text_handler.setFormatter(formatter)
        logging.getLogger().addHandler(self.text_handler)
    def apply_filter(self):
        filter_text = self.filter_var.get().lower()
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, f"Filter applied: {filter_text}\n")
        self.log_text.configure(state='disabled')
