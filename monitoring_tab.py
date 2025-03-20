import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os, time, threading, logging, difflib
from event_handler import FIMEventHandler
from utils import compute_sha256, send_email_alert

class MonitoringTab(ttk.Frame):
    def __init__(self, parent, db, get_alert_email, backup_folder, preselected_files=None):
        super().__init__(parent)
        self.db = db
        self.get_alert_email = get_alert_email
        self.backup_folder = backup_folder
        self.system_file = None  # للملف الذي سيتم مراقبته في وضع Real-Time (إذا كان ملف واحد)
        self.rt_observer = None
        self.scheduled_files = {}  # للملفات المجدولة: {file_path: {sensitivity, last_scanned}}
        self.sensitivity_intervals = {"High": 30, "Medium": 60, "Low": 120}
        self.scheduled_scanning_running = True

        # متغير لتحديد وضع المراقبة: "Real-Time" أو "Scheduled"
        self.monitoring_mode = tk.StringVar(value="Real-Time")
        # متغير لتحديد فترة الفحص المجدول (بالثواني)
        self.scheduled_frequency = tk.IntVar(value=60)
        
        # قائمة الملفات المُختارة
        self.selected_files = []
        if preselected_files:
            self.selected_files = list(preselected_files)
            if len(preselected_files) == 1:
                self.system_file = preselected_files[0]

        self.setup_styles()
        self.create_widgets()
        self.scheduled_thread = threading.Thread(target=self.scheduled_scan_loop, daemon=True)
        self.scheduled_thread.start()

    def setup_styles(self):
        style = ttk.Style()
        style.configure("TFrame", background="#f8f9fa")
        style.configure("TLabel", background="#f8f9fa", font=("Helvetica", 12))
        style.configure("TButton", font=("Helvetica", 11), padding=5)
        style.configure("TLabelframe", background="#f8f9fa", font=("Helvetica", 13, "bold"))
        style.configure("TLabelframe.Label", background="#f8f9fa")

    def create_widgets(self):
        # إطار عرض الملفات المُختارة
        selected_frame = ttk.LabelFrame(self, text="Selected Files")
        selected_frame.pack(fill=tk.X, padx=10, pady=10)
        self.selected_files_label = ttk.Label(selected_frame, text=self.get_selected_files_text(), style="TLabel")
        self.selected_files_label.pack(padx=10, pady=5)
        
        # إطار لاختيار وضع المراقبة
        mode_frame = ttk.LabelFrame(self, text="Monitoring Mode")
        mode_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Radiobutton(mode_frame, text="Real-Time Monitoring", variable=self.monitoring_mode, value="Real-Time", command=self.on_mode_change).pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Radiobutton(mode_frame, text="Scheduled Monitoring", variable=self.monitoring_mode, value="Scheduled", command=self.on_mode_change).pack(side=tk.LEFT, padx=10, pady=5)
        
        # خيارات Scheduled Monitoring (تحديد فترة الفحص)
        self.scheduled_options_frame = ttk.Frame(self)
        self.scheduled_options_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(self.scheduled_options_frame, text="Scan Frequency (sec):", style="TLabel").pack(side=tk.LEFT, padx=5)
        self.freq_entry = ttk.Entry(self.scheduled_options_frame, textvariable=self.scheduled_frequency, width=10)
        self.freq_entry.pack(side=tk.LEFT, padx=5)
        self.on_mode_change()
        
        # زر بدء المراقبة الموحد
        start_button = ttk.Button(self, text="يلا ابدا الشغل", command=self.start_monitoring)
        start_button.pack(pady=10)
        
        # قسم Real-Time Monitoring (يظهر في وضع Real-Time)
        self.rt_frame = ttk.LabelFrame(self, text="Real-Time Monitoring")
        self.rt_frame.pack(fill=tk.X, padx=10, pady=10)
        self.lbl_system_file = ttk.Label(self.rt_frame, text="Selected File: " + (self.system_file if self.system_file else "Not selected"), style="TLabel")
        self.lbl_system_file.pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Button(self.rt_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side=tk.LEFT, padx=10)
        
        # قسم Scheduled Scanning (يظهر في وضع Scheduled)
        self.ss_frame = ttk.LabelFrame(self, text="Scheduled Scanning")
        self.ss_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(self.ss_frame, text="Add File", command=self.add_scheduled_file).pack(side=tk.LEFT, padx=10)
        ttk.Button(self.ss_frame, text="Remove Selected", command=self.remove_scheduled_file).pack(side=tk.LEFT, padx=10)
        self.ss_listbox = tk.Listbox(self.ss_frame, width=90, height=5, font=("Helvetica", 10))
        self.ss_listbox.pack(padx=10, pady=10)
        
        # صندوق التنبيهات
        alert_frame = ttk.LabelFrame(self, text="Alert Box")
        alert_frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)
        self.alert_box = tk.Text(alert_frame, height=10, wrap=tk.WORD, font=("Helvetica", 10))
        self.alert_box.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)
        self.alert_box.configure(state='disabled')

    def get_selected_files_text(self):
        if not self.selected_files:
            return "No files selected."
        elif len(self.selected_files) == 1:
            return self.selected_files[0]
        else:
            return "\n".join(self.selected_files)

    def on_mode_change(self):
        if self.monitoring_mode.get() == "Scheduled":
            self.scheduled_options_frame.pack(fill=tk.X, padx=10, pady=5)
        else:
            self.scheduled_options_frame.forget()

    def display_alert(self, message):
        self.alert_box.configure(state='normal')
        self.alert_box.insert(tk.END, message + "\n" + "="*60 + "\n")
        self.alert_box.configure(state='disabled')
        self.alert_box.see(tk.END)

    def start_monitoring(self):
        mode = self.monitoring_mode.get()
        if mode == "Real-Time":
            if not self.selected_files:
                default_file = (r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/passwd")
                self.selected_files = [default_file]
                self.system_file = default_file
                self.selected_files_label.config(text=self.get_selected_files_text())
                self.lbl_system_file.config(text="Selected File: " + default_file)
            else:
                if len(self.selected_files) == 1:
                    self.system_file = self.selected_files[0]
                    self.lbl_system_file.config(text="Selected File: " + self.system_file)
                else:
                    self.lbl_system_file.config(text="Selected Files: " + ", ".join(self.selected_files))
            from watchdog.observers import Observer
            event_handler = FIMEventHandler(self.db, target_files=self.selected_files,
                                            get_alert_email=self.get_alert_email,
                                            backup_folder=self.backup_folder,
                                            alert_callback=self.display_alert)
            self.rt_observer = Observer()
            monitored_dirs = set()
            for file in self.selected_files:
                monitored_dirs.add(os.path.dirname(file))
            for directory in monitored_dirs:
                self.rt_observer.schedule(event_handler, directory, recursive=False)
            self.rt_observer.start()
            logging.info(f"Started Real-Time monitoring for files:\n{chr(10).join(self.selected_files)}")
        elif mode == "Scheduled":
            messagebox.showinfo("Scheduled Monitoring", "Scheduled monitoring will run automatically based on the set frequency.")
        else:
            messagebox.showerror("Error", "Please select a valid monitoring mode.")

    def stop_monitoring(self):
        if self.rt_observer:
            self.rt_observer.stop()
            self.rt_observer.join()
            logging.info("Stopped monitoring.")

    def add_scheduled_file(self):
        file_path = filedialog.askopenfilename(title="Select a File for Scheduled Scanning")
        if file_path:
            sensitivity = self.ask_sensitivity()
            if sensitivity:
                if file_path not in self.scheduled_files:
                    self.scheduled_files[file_path] = {"sensitivity": sensitivity, "last_scanned": 0}
                    self.ss_listbox.insert(tk.END, f"{file_path} - {sensitivity}")
                    if file_path not in self.selected_files:
                        self.selected_files.append(file_path)
                        self.selected_files_label.config(text=self.get_selected_files_text())
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
            if file_path in self.selected_files:
                self.selected_files.remove(file_path)
                self.selected_files_label.config(text=self.get_selected_files_text())
            logging.info(f"Removed scheduled file: {file_path}")

    def ask_sensitivity(self):
        dialog = tk.Toplevel(self)
        dialog.title("Select Sensitivity")
        sensitivity_var = tk.StringVar(value="High")
        ttk.Label(dialog, text="Select Sensitivity:").pack(pady=10)
        ttk.OptionMenu(dialog, sensitivity_var, "High", "High", "Medium", "Low").pack(pady=5)
        result = {"value": None}
        def on_ok():
            result["value"] = sensitivity_var.get()
            dialog.destroy()
        ttk.Button(dialog, text="OK", command=on_ok).pack(pady=10)
        self.wait_window(dialog)
        return result["value"]

    def scheduled_scan_loop(self):
        while self.scheduled_scanning_running:
            if self.monitoring_mode.get() != "Scheduled":
                time.sleep(5)
                continue
            current_time = time.time()
            interval = self.scheduled_frequency.get()
            for file_path, data in list(self.scheduled_files.items()):
                if current_time - data["last_scanned"] >= interval:
                    if os.path.isfile(file_path):
                        new_hash = compute_sha256(file_path)
                        if new_hash is None:
                            continue
                        stored_hash = self.db.get_hash(file_path)
                        current_mod_time = os.path.getmtime(file_path)
                        if stored_hash is None:
                            self.db.update_hash(file_path, new_hash, current_mod_time)
                            logging.info(f"Scheduled scan: New file added: {file_path}")
                        elif stored_hash != new_hash:
                            self.db.update_hash(file_path, new_hash, current_mod_time)
                            alert_msg = (
                                f"Scheduled scan alert:\n"
                                f"File: {file_path}\n"
                                f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_mod_time))}\n"
                                f"Old Hash: {stored_hash}\n"
                                f"New Hash: {new_hash}"
                            )
                            logging.warning(alert_msg)
                            send_email_alert("Scheduled File Modification Alert", alert_msg, self.get_alert_email())
                            self.display_alert(alert_msg)
                    else:
                        logging.warning(f"Scheduled scan: File not found: {file_path}")
                    self.scheduled_files[file_path]["last_scanned"] = current_time
            time.sleep(5)
