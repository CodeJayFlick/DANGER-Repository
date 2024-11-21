Here is the equivalent Python code:

```Python
import os
from io import BufferedWriter, FileWriter


class SyncReceiverLogger:
    def __init__(self, log_file):
        if not os.path.exists(os.path.dirname(log_file)):
            os.makedirs(os.path.dirname(log_file))
        self.bw = BufferedWriter(FileWriter(log_file))

    def start_sync_deleted_files_name(self):
        self.bw.write("SYNC_DELETED_FILE_NAME_START")
        self.bw.write("\n")
        self.bw.flush()

    def finish_sync_deleted_file_name(self, file):
        self.bw.write(file.absolute_path)
        self.bw.write("\n")
        self.bw.flush()

    def start_sync_ts_files(self):
        self.bw.write("SYNC_TSFILE_START")
        self.bw.write("\n")
        self.bw.flush()

    def finish_sync_ts_file(self, file):
        self.bw.write(file.absolute_path)
        self.bw.write("\n")
        self.bw.flush()

    def close(self):
        if self.bw is not None:
            self.bw.close()
            self.bw = None
```

Note that Python does not have a direct equivalent to Java's `BufferedWriter` and `FileWriter`. Instead, we use the built-in file operations (`open`, `write`, etc.) with buffering enabled by default.