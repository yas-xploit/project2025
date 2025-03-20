import sqlite3

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
