import tkinter as tk
import os, time, hashlib, shutil, logging
import smtplib
from email.mime.text import MIMEText
import numpy as np
from sklearn.ensemble import IsolationForest

def compute_sha256(file_path):
    """
    Computes the SHA-256 hash for the given file.
    """
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        logging.error(f"Error computing hash for {file_path}: {e}")
        return None

def send_email_alert(subject, message, to_email):
    """
    Sends an email alert using the provided SMTP settings.
    **تم تعطيل هذه الوظيفة حالياً، حيث لا يتم إرسال رسائل البريد الإلكتروني.
    """
    # فقط نسجل رسالة التنبيه بدلاً من إرسالها
    logging.info(f"Email alert disabled. Subject: {subject}, To: {to_email}, Message: {message}")


def automated_backup(file_path, backup_folder):
    """
    Creates a backup of the specified file in the given backup folder.
    """
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
    """
    Detects anomalies in the provided file change data using IsolationForest.
    """
    if not file_change_data:
        return []
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    data = np.array(file_change_data)
    model.fit(data)
    predictions = model.predict(data)
    anomalies = [i for i, pred in enumerate(predictions) if pred == -1]
    logging.info(f"Anomaly detection found anomalies at indices: {anomalies}")
    return anomalies

class TextHandler(logging.Handler):
    """
    Logging handler that writes log messages to a Tkinter Text widget.
    """
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
