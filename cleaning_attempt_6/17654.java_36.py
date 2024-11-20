import os

class SyncSenderLogger:
    def __init__(self, file_path):
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))
        self.bw = open(file_path, 'a')

    def start_sync_deleted_files_name(self):
        self.bw.write("SYNC_DELETED_FILE_NAME_START\n")
        self.bw.flush()

    def finish_sync_deleted_file_name(self, file_path):
        self.bw.write(f"{file_path}\n")
        self.bw.flush()

    def start_sync_ts_files(self):
        self.bw.write("SYNC_TSFILE_START\n")
        self.bw.flush()

    def finish_sync_ts_file(self, file_path):
        self.bw.write(f"{file_path}\n")
        self.bw.flush()

    def close(self):
        if self.bw:
            self.bw.close()
            self.bw = None
