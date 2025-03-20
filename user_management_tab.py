import tkinter as tk
from tkinter import ttk
import logging

class UserManagementTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.users = {"admin": {"password": "admin123", "role": "admin"}}
        self.current_user = None
        self.create_widgets()
    def create_widgets(self):
        login_frame = ttk.LabelFrame(self, text="User Login")
        login_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.username_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.username_var, width=20).grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.password_var, show="*", width=20).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(login_frame, text="Login", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)
        self.login_status = ttk.Label(self, text="Not logged in", foreground="red")
        self.login_status.pack(pady=5)
    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        user = self.users.get(username)
        if user and user["password"] == password:
            self.current_user = username
            self.login_status.config(text=f"Logged in as {username} ({user['role']})", foreground="green")
            logging.info(f"User {username} logged in.")
        else:
            self.login_status.config(text="Login failed", foreground="red")
            logging.warning("Failed login attempt.")
