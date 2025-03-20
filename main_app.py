import tkinter as tk
from tkinter import ttk, scrolledtext
import threading, logging, os
from api import run_api
from database import FileDatabase
from home_page import HomePage
from monitoring_tab import MonitoringTab
from dashboard_tab import DashboardTab
from logs_tab import LogsTab
from settings_tab import SettingsTab
from user_management_tab import UserManagementTab
from utils import TextHandler

class MainApplication(tk.Tk):
    def __init__(self, preselected_files=None):
        super().__init__()
        self.title("Comprehensive File Integrity Monitoring System")
        self.geometry("1000x800")
        self.resizable(False, False)
        # Start REST API in a separate thread
        self.api_thread = threading.Thread(target=run_api, daemon=True)
        self.api_thread.start()
        self.db = FileDatabase()
        self.alert_email = tk.StringVar(value="your_email@example.com")
        self.backup_folder = tk.StringVar(value=os.path.expanduser("~") + "/file_backups")
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.monitoring_tab = MonitoringTab(self.notebook, self.db, self.get_alert_email, self.backup_folder.get(), preselected_files)
        self.notebook.add(self.monitoring_tab, text="Monitoring")
        self.dashboard_tab = DashboardTab(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.logs_tab = LogsTab(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        self.settings_tab = SettingsTab(self.notebook, self)
        self.notebook.add(self.settings_tab, text="Settings")
        self.user_management_tab = UserManagementTab(self.notebook)
        self.notebook.add(self.user_management_tab, text="User Management")
        email_frame = ttk.LabelFrame(self, text="Alert Email Settings")
        email_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(email_frame, text="Alert Email:").pack(side=tk.LEFT, padx=5, pady=5)
        self.email_entry = ttk.Entry(email_frame, textvariable=self.alert_email, width=40)
        self.email_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(self, state='disabled', width=120, height=10)
        self.log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        text_handler = TextHandler(self.log_text)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        text_handler.setFormatter(formatter)
        logging.getLogger().addHandler(text_handler)
        logging.getLogger().setLevel(logging.INFO)
    def get_alert_email(self):
        return self.alert_email.get()
    def on_closing(self):
        self.monitoring_tab.scheduled_scanning_running = False
        if self.monitoring_tab.rt_observer:
            self.monitoring_tab.rt_observer.stop()
            self.monitoring_tab.rt_observer.join()
        self.destroy()

if __name__ == "__main__":
    # Launch home page first
    home = HomePage()
    home.mainloop()
    # Retrieve preselected files and launch main application
    main_app = MainApplication(preselected_files=home.preselected_files)
    main_app.protocol("WM_DELETE_WINDOW", main_app.on_closing)
    main_app.mainloop()
