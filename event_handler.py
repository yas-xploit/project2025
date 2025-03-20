from watchdog.events import FileSystemEventHandler
import os, time, logging, difflib
from utils import compute_sha256, send_email_alert, automated_backup

class FIMEventHandler(FileSystemEventHandler):
    """
    Handles file events (real-time monitoring) and triggers alerts with detailed information.
    Supports monitoring multiple files.
    """
    def __init__(self, db, target_files=None, get_alert_email=None, backup_folder=None, alert_callback=None):
        super().__init__()
        self.db = db
        # تحويل قائمة الملفات إلى مسارات مطلقة إن وُجدت
        self.target_files = [os.path.abspath(f) for f in target_files] if target_files else None
        self.get_alert_email = get_alert_email if get_alert_email else lambda: "your_email@example.com"
        self.backup_folder = backup_folder
        self.alert_callback = alert_callback  # callback لتحديث صندوق التنبيهات في الواجهة
        self.last_contents = {}  # لتخزين المحتوى السابق لكل ملف {file_path: list_of_lines}

    def process_event(self, event, event_type):
        if event.is_directory:
            return
        file_path = os.path.abspath(event.src_path)
        # إذا كانت target_files محددة، تحقق أن الملف ضمنها
        if self.target_files is not None and file_path not in self.target_files:
            return

        logging.info(f"{event_type.capitalize()} event for file: {file_path}")
        new_hash = compute_sha256(file_path)
        if new_hash is None:
            return
        stored_hash = self.db.get_hash(file_path)
        current_mod_time = os.path.getmtime(file_path)
        
        # قراءة المحتوى الجديد للملف
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                new_content = f.readlines()
        except Exception as e:
            logging.error(f"Error reading file content: {e}")
            new_content = []

        old_content = self.last_contents.get(file_path)
        diff_text = ""
        if old_content is not None and event_type == "modified":
            diff_lines = list(difflib.unified_diff(old_content, new_content,
                                                   fromfile="Old Version", tofile="New Version", lineterm=""))
            diff_text = "\n".join(diff_lines)
        self.last_contents[file_path] = new_content

        if stored_hash is None:
            self.db.update_hash(file_path, new_hash, current_mod_time)
            logging.info(f"New file added: {file_path}")
        elif stored_hash != new_hash:
            if self.backup_folder:
                automated_backup(file_path, self.backup_folder)
            self.db.update_hash(file_path, new_hash, current_mod_time)
            timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_mod_time))
            alert_message = (
                "======================== ALERT ========================\n"
                f"File: {file_path}\n"
                f"Time: {timestamp_str}\n"
                "------------------------------------------------------\n"
                "Old Hash (SHA-256):\n"
                f"    {stored_hash}\n"
                "New Hash (SHA-256):\n"
                f"    {new_hash}\n"
                "------------------------------------------------------\n"
                "Diff:\n"
                f"{diff_text}\n"
                "======================================================\n"
            )
            logging.warning(alert_message)
            send_email_alert("File Modification Alert", alert_message, self.get_alert_email())
            if self.alert_callback:
                self.alert_callback(alert_message)

    def on_created(self, event):
        self.process_event(event, "created")

    def on_modified(self, event):
        self.process_event(event, "modified")

    def on_deleted(self, event):
        self.process_event(event, "deleted")
