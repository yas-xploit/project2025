import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

class HomePage(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Welcome to File Integrity Monitoring System")
        self.geometry("600x400")
        self.configure(bg="white")
        self.preselected_files = []
        self.create_widgets()
    
    def create_widgets(self):
        title_label = ttk.Label(self, text="Welcome", font=("Arial", 28), background="white")
        title_label.pack(pady=30)
        description = ttk.Label(self, text="Choose an option to start using the application", 
                                font=("Arial", 14), background="white")
        description.pack(pady=20)
        btn_custom = ttk.Button(self, text="Select Files to Monitor", command=self.option_custom)
        btn_custom.pack(pady=10, ipadx=10, ipady=5)
        btn_default = ttk.Button(self, text="Use Important Windows Files", command=self.option_default)
        btn_default.pack(pady=10, ipadx=10, ipady=5)
    
    def option_custom(self):
        files = filedialog.askopenfilenames(title="Select Files to Monitor")
        if files:
            self.preselected_files = list(files)
            self.destroy()
    
    def option_default(self):
        default_files = [
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SECURITY"
        ]
        self.preselected_files = [f for f in default_files if os.path.isfile(f)]
        if not self.preselected_files:
            messagebox.showerror("Error", "Default Windows files not found on this system.")
        else:
            self.destroy()
