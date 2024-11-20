import os

class LoadLogger:
    def __init__(self, log_file):
        if not os.path.exists(os.path.dirname(log_file)):
            os.makedirs(os.path.dirname(log_file))
        self.bw = open(log_file, 'a')

    def start_load_deleted_files(self):
        self.bw.write('LOAD_DELETED_FILE_NAME_START\n')
        self.bw.flush()

    def finish_load_deleted_file(self, file_path):
        self.bw.write(file_path + '\n')
        self.bw.flush()

    def start_load_tsfiles(self):
        self.bw.write('LOAD_TSFILE_START\n')
        self.bw.flush()

    def finish_load_tsfile(self, file_path):
        self.bw.write(file_path + '\n')
        self.bw.flush()

    def close(self):
        if self.bw:
            self.bw.close()
            self.bw = None
