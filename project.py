import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading, time, os, hashlib, sqlite3, logging, smtplib, platform, shutil, json
from email.mime.text import MIMEText
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from flask import Flask, jsonify, request
from sklearn.ensemble import IsolationForest
import numpy as np

# ------------------- Custom Logging Handler -------------------
class TextHandler(logging.Handler):
    """Logging handler that writes log messages to a Tkinter Text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + "\n")
            self.text_widget.configure(state='disabled')
            self.text_widget.yview(tk.END)
        self.text_widget.after(0, append)

# ------------------- Database Component -------------------
class FileDatabase:
    def __init__(self, db_path="file_hashes.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_table()
    def create_table(self):
        query = '''
        CREATE TABLE IF NOT EXISTS file_hashes (
            file_path TEXT PRIMARY KEY,
            sha256_hash TEXT,
            last_modified REAL
        );
        '''
        self.conn.execute(query)
        self.conn.commit()
    def get_hash(self, file_path):
        cursor = self.conn.cursor()
        cursor.execute("SELECT sha256_hash FROM file_hashes WHERE file_path = ?", (file_path,))
        row = cursor.fetchone()
        return row[0] if row else None
    def update_hash(self, file_path, sha256_hash, last_modified):
        if self.get_hash(file_path) is None:
            self.conn.execute("INSERT INTO file_hashes (file_path, sha256_hash, last_modified) VALUES (?, ?, ?)", 
                              (file_path, sha256_hash, last_modified))
        else:
            self.conn.execute("UPDATE file_hashes SET sha256_hash = ?, last_modified = ? WHERE file_path = ?",
                              (sha256_hash, last_modified, file_path))
        self.conn.commit()
    def remove_file(self, file_path):
        self.conn.execute("DELETE FROM file_hashes WHERE file_path = ?", (file_path,))
        self.conn.commit()

# ------------------- Utility Functions -------------------
def compute_sha256(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        logging.error(f"Error computing hash for {file_path}: {e}")
        return None

def send_email_alert(subject, message, to_email):
    # NOTE: Update these SMTP settings with valid credentials.
    smtp_server = "smtp.example.com"
    smtp_port = 587
    smtp_username = "your_username"
    smtp_password = "your_password"
    from_email = "alert@example.com"
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(from_email, [to_email], msg.as_string())
        logging.info(f"Alert email sent to {to_email}")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def automated_backup(file_path, backup_folder):
    if not os.path.exists(backup_folder):
        os.makedirs(backup_folder)
    timestamp = time.strftime("%Y%m%d%H%M%S")
    backup_file = os.path.join(backup_folder, f"{os.path.basename(file_path)}_{timestamp}")
    try:
        shutil.copy2(file_path, backup_file)
        logging.info(f"Backup created for {file_path} at {backup_file}")
    except Exception as e:
        logging.error(f"Error backing up {file_path}: {e}")

def anomaly_detection(file_change_data):
    # Stub: Use IsolationForest to detect anomalies
    if not file_change_data:
        return []
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    data = np.array(file_change_data)
    model.fit(data)
    predictions = model.predict(data)
    anomalies = [i for i, pred in enumerate(predictions) if pred == -1]
    logging.info(f"Anomaly detection found anomalies at indices: {anomalies}")
    return anomalies

# ------------------- REST API for Integration -------------------
app_flask = Flask(__name__)
system_metrics = {"alerts_count": 0, "files_monitored": 0}
@app_flask.route("/api/metrics", methods=["GET"])
def get_metrics():
    return jsonify(system_metrics)
@app_flask.route("/api/alert", methods=["POST"])
def receive_alert():
    data = request.json
    logging.info(f"Received alert via API: {data}")
    return jsonify({"status": "received"}), 200
def run_api():
    app_flask.run(port=5000)

# ------------------- Real-Time Monitoring Event Handler -------------------
class FIMEventHandler(threading.Thread):
    """
    Handles file events (real-time monitoring) and triggers alerts.
    Also calls automated_backup as an example of versioning.
    """
    def __init__(self, db: FileDatabase, target_file=None, get_alert_email=None, backup_folder=None):
        super().__init__()
        self.db = db
        self.target_file = target_file
        self.get_alert_email = get_alert_email if get_alert_email else lambda: "your_email@example.com"
        self.backup_folder = backup_folder
    def run_event(self, event, event_type):
        if event.is_directory:
            return
        file_path = event.src_path
        if self.target_file and os.path.abspath(file_path) != os.path.abspath(self.target_file):
            return
        logging.info(f"{event_type.capitalize()} event for file: {file_path}")
        new_hash = compute_sha256(file_path)
        if new_hash is None:
            return
        stored_hash = self.db.get_hash(file_path)
        current_mod_time = os.path.getmtime(file_path)
        if stored_hash is None:
            self.db.update_hash(file_path, new_hash, current_mod_time)
            logging.info(f"New file added: {file_path}")
        elif stored_hash != new_hash:
            # Before updating, create a backup
            if self.backup_folder:
                automated_backup(file_path, self.backup_folder)
            self.db.update_hash(file_path, new_hash, current_mod_time)
            alert_message = f"File {file_path} modified.\nOld: {stored_hash}\nNew: {new_hash}"
            logging.warning(alert_message)
            send_email_alert("File Modification Alert", alert_message, self.get_alert_email())
    def on_created(self, event):
        self.run_event(event, "created")
    def on_modified(self, event):
        self.run_event(event, "modified")
    def on_deleted(self, event):
        self.run_event(event, "deleted")

# ------------------- Home Page (Splash Screen) -------------------
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
        # Option 1: Let user manually select files
        btn_custom = ttk.Button(self, text="Select Files to Monitor", command=self.option_custom)
        btn_custom.pack(pady=10, ipadx=10, ipady=5)
        # Option 2: Automatically use important Windows files
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

# ------------------- Monitoring Tab -------------------
class MonitoringTab(ttk.Frame):
    def __init__(self, parent, db, get_alert_email, backup_folder, preselected_files=None):
        super().__init__(parent)
        self.db = db
        self.get_alert_email = get_alert_email
        self.backup_folder = backup_folder
        self.system_file = None
        self.rt_observer = None
        self.scheduled_files = {}  # {file_path: {sensitivity, last_scanned}}
        self.sensitivity_intervals = {"High": 30, "Medium": 60, "Low": 120}
        self.scheduled_scanning_running = True
        self.create_widgets()
        # If preselected_files is provided, set them up:
        if preselected_files:
            if len(preselected_files) == 1:
                self.system_file = preselected_files[0]
                self.lbl_system_file.config(text=self.system_file)
            else:
                for file in preselected_files:
                    self.scheduled_files[file] = {"sensitivity": "High", "last_scanned": 0}
                    self.ss_listbox.insert(tk.END, f"{file} - High")
        self.scheduled_thread = threading.Thread(target=self.scheduled_scan_loop, daemon=True)
        self.scheduled_thread.start()
    def create_widgets(self):
        rt_frame = ttk.LabelFrame(self, text="Real-Time Monitoring")
        rt_frame.pack(fill=tk.X, padx=5, pady=5)
        self.lbl_system_file = ttk.Label(rt_frame, text="Default system file selected")
        self.lbl_system_file.pack(side=tk.LEFT, padx=5)
        ttk.Button(rt_frame, text="Start RT Monitoring", command=self.start_system_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(rt_frame, text="Stop RT Monitoring", command=self.stop_system_monitoring).pack(side=tk.LEFT, padx=5)
        ss_frame = ttk.LabelFrame(self, text="Scheduled Scanning")
        ss_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(ss_frame, text="Add File", command=self.add_scheduled_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(ss_frame, text="Remove Selected", command=self.remove_scheduled_file).pack(side=tk.LEFT, padx=5)
        self.ss_listbox = tk.Listbox(ss_frame, width=80, height=5)
        self.ss_listbox.pack(padx=5, pady=5)
    def start_system_monitoring(self):
        if not self.system_file:
            self.system_file = (r"C:\Windows\System32\drivers\etc\hosts" if platform.system() == "Windows" else "/etc/passwd")
        from watchdog.observers import Observer
        event_handler = FIMEventHandler(self.db, target_file=self.system_file,
                                        get_alert_email=self.get_alert_email,
                                        backup_folder=self.backup_folder)
        self.rt_observer = Observer()
        self.rt_observer.schedule(event_handler, os.path.dirname(self.system_file), recursive=False)
        self.rt_observer.start()
        logging.info(f"Started RT monitoring for {self.system_file}")
    def stop_system_monitoring(self):
        if self.rt_observer:
            self.rt_observer.stop()
            self.rt_observer.join()
            logging.info("Stopped RT monitoring.")
    def add_scheduled_file(self):
        file_path = filedialog.askopenfilename(title="Select a File for Scheduled Scanning")
        if file_path:
            sensitivity = self.ask_sensitivity()
            if sensitivity:
                if file_path not in self.scheduled_files:
                    self.scheduled_files[file_path] = {"sensitivity": sensitivity, "last_scanned": 0}
                    self.ss_listbox.insert(tk.END, f"{file_path} - {sensitivity}")
                    logging.info(f"Added scheduled file: {file_path} with {sensitivity} sensitivity")
    def remove_scheduled_file(self):
        selection = self.ss_listbox.curselection()
        if selection:
            index = selection[0]
            entry = self.ss_listbox.get(index)
            file_path = entry.split(" - ")[0]
            if file_path in self.scheduled_files:
                del self.scheduled_files[file_path]
            self.ss_listbox.delete(index)
            logging.info(f"Removed scheduled file: {file_path}")
    def ask_sensitivity(self):
        dialog = tk.Toplevel(self)
        dialog.title("Select Sensitivity")
        sensitivity_var = tk.StringVar(value="High")
        ttk.Label(dialog, text="Select Sensitivity:").pack(pady=5)
        ttk.OptionMenu(dialog, sensitivity_var, "High", "High", "Medium", "Low").pack(pady=5)
        result = {"value": None}
        def on_ok():
            result["value"] = sensitivity_var.get()
            dialog.destroy()
        ttk.Button(dialog, text="OK", command=on_ok).pack(pady=5)
        self.wait_window(dialog)
        return result["value"]
    def scheduled_scan_loop(self):
        while self.scheduled_scanning_running:
            current_time = time.time()
            for file_path, data in list(self.scheduled_files.items()):
                interval = self.sensitivity_intervals.get(data["sensitivity"], 60)
                if current_time - data["last_scanned"] >= interval:
                    if os.path.isfile(file_path):
                        new_hash = compute_sha256(file_path)
                        if new_hash is None: continue
                        stored_hash = self.db.get_hash(file_path)
                        current_mod_time = os.path.getmtime(file_path)
                        if stored_hash is None:
                            self.db.update_hash(file_path, new_hash, current_mod_time)
                            logging.info(f"Scheduled scan: New file added: {file_path}")
                        elif stored_hash != new_hash:
                            self.db.update_hash(file_path, new_hash, current_mod_time)
                            alert_msg = f"Scheduled scan: {file_path} modified.\nOld: {stored_hash}\nNew: {new_hash}"
                            logging.warning(alert_msg)
                            send_email_alert("Scheduled File Modification Alert", alert_msg, self.get_alert_email())
                    else:
                        logging.warning(f"Scheduled scan: File not found: {file_path}")
                    self.scheduled_files[file_path]["last_scanned"] = current_time
            time.sleep(5)

# ------------------- Dashboard Tab -------------------
class DashboardTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()
    def create_widgets(self):
        fig, ax = plt.subplots(figsize=(5,3))
        ax.plot([1,2,3,4], [10,20,15,30], marker='o')
        ax.set_title("Analytics Chart")
        canvas = FigureCanvasTkAgg(fig, master=self)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

# ------------------- Logs Tab -------------------
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

# ------------------- Settings Tab -------------------
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

# ------------------- User Management Tab -------------------
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

# ------------------- Main Application -------------------
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

# ------------------- Main Program -------------------
if __name__ == "__main__":
    # Launch home page first
    home = HomePage()
    home.mainloop()
    # Retrieve preselected files from home page and launch main app
    main_app = MainApplication(preselected_files=home.preselected_files)
    main_app.protocol("WM_DELETE_WINDOW", main_app.on_closing)
    main_app.mainloop()
