import os
import logging
from collections import defaultdict

class SyncSenderLogAnalyzer:
    def __init__(self, sender_path):
        self.sender_path = sender_path
        self.current_local_file = os.path.join(sender_path, 'current.local')
        self.last_local_file = os.path.join(sender_path, 'last.local')
        self.sync_log_file = os.path.join(sender_path, 'sync.log')

    def recover(self):
        if os.path.exists(self.current_local_file) and not os.path.exists(self.last_local_file):
            os.rename(self.current_local_file, self.last_local_file)
        else:
            deleted_files = set()
            new_files = set()
            last_local_files = defaultdict(set)

            with open(self.last_local_file, 'r') as f:
                for line in f:
                    last_local_files[line.strip()].add(line.strip())

            with open(self.sync_log_file, 'r') as f:
                mode = 0
                for line in f:
                    if line == SyncSenderLogger.SYNC_DELETED_FILE_NAME_START:
                        mode = -1
                    elif line == SyncSenderLogger.SYNC_TSFILE_START:
                        mode = 1
                    else:
                        if mode == -1:
                            deleted_files.add(line.strip())
                        elif mode == 1:
                            new_files.add(line.strip())

            last_local_files['deleted'].update(deleted_files)
            last_local_files['new'].update(new_files)

            with open(self.last_local_file, 'w') as f:
                for line in sorted(last_local_files['new']):
                    f.write(line + '\n')

            os.remove(os.path.join(self.sender_path, 'data.snapshot'))
            os.remove(self.sync_log_file)

    def load_last_local_files(self):
        if not os.path.exists(self.last_local_file):
            logging.info("last local file {} doesn't exist.".format(self.last_local_file))
            return

        try:
            with open(self.last_local_file, 'r') as f:
                for line in f:
                    last_local_files.add(line.strip())
        except Exception as e:
            logging.error("Can not load last local file list from file {}".format(self.last_local_file), e)

    def load_logger(self):
        if not os.path.exists(self.sync_log_file):
            logging.info("log file {} doesn't exist.".format(self.sync_log_file))
            return

        try:
            with open(self.sync_log_file, 'r') as f:
                mode = 0
                for line in f:
                    if line == SyncSenderLogger.SYNC_DELETED_FILE_NAME_START:
                        mode = -1
                    elif line == SyncSenderLogger.SYNC_TSFILE_START:
                        mode = 1
                    else:
                        if mode == -1:
                            deleted_files.add(line.strip())
                        elif mode == 1:
                            new_files.add(line.strip())

        except Exception as e:
            logging.error("Can not load last local file list from file {}".format(self.last_local_file), e)

    def update_last_local_file(self, current_local_files):
        try:
            with open(self.current_local_file, 'w') as f:
                for line in sorted(current_local_files):
                    f.write(line + '\n')
            f.flush()
        except Exception as e:
            logging.error("Can not clear sync log {}".format(self.sync_log_file), e)

        os.remove(self.last_local_file)
        os.rename(self.current_local_file, self.last_local_file)
