import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os, json
import logging

class SettingsTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.create_widgets()
    def create_widgets(self):
        config_frame = ttk.LabelFrame(self, text="Configuration Settings")
        config_frame.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)
        ttk.Label(config_frame, text="High Sensitivity Interval (sec):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.high_interval = tk.IntVar(value=30)
        ttk.Entry(config_frame, textvariable=self.high_interval, width=10).grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(config_frame, text="Medium Sensitivity Interval (sec):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.medium_interval = tk.IntVar(value=60)
        ttk.Entry(config_frame, textvariable=self.medium_interval, width=10).grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(config_frame, text="Low Sensitivity Interval (sec):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.low_interval = tk.IntVar(value=120)
        ttk.Entry(config_frame, textvariable=self.low_interval, width=10).grid(row=2, column=1, padx=5, pady=5)
        ttk.Label(config_frame, text="Backup Folder:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.backup_folder = tk.StringVar(value=os.path.expanduser("~") + "/file_backups")
        ttk.Entry(config_frame, textvariable=self.backup_folder, width=40).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(config_frame, text="Select Folder", command=self.select_backup_folder).grid(row=3, column=2, padx=5, pady=5)
        ttk.Button(config_frame, text="Save Configuration", command=self.save_configuration).grid(row=4, column=0, columnspan=3, pady=10)
    def select_backup_folder(self):
        folder = filedialog.askdirectory(title="Select Backup Folder")
        if folder:
            self.backup_folder.set(folder)
    def save_configuration(self):
        config = {
            "high_interval": self.high_interval.get(),
            "medium_interval": self.medium_interval.get(),
            "low_interval": self.low_interval.get(),
            "backup_folder": self.backup_folder.get()
        }
        with open("config.json", "w") as f:
            json.dump(config, f, indent=4)
        messagebox.showinfo("Configuration", "Configuration saved successfully.")
        self.app.monitoring_tab.sensitivity_intervals = {
            "High": self.high_interval.get(),
            "Medium": self.medium_interval.get(),
            "Low": self.low_interval.get()
        }
        logging.info("Configuration updated.")
