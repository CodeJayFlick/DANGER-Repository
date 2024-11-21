Here is the translation of the Java code into Python:

```Python
import os
import logging
from io import BufferedWriter, FileWriter
from threading import Lock


class SettleLog:
    logger = logging.getLogger(__name__)
    COMMA_SEPERATOR = ","
    config = None  # assume this will be set elsewhere in your program

    SETTLE_DIR = "settle"
    SETTLE_LOG_NAME = "settle.txt"

    settle_log_path = None
    _lock = Lock()

    def __init__(self):
        self.settle_log_writer = None

    @property
    def settle_log_path(self):
        return self._settle_log_path

    @settle_log_path.setter
    def settle_log_path(self, value):
        self._settle_log_path = value

    def create_settle_log(self):
        try:
            if not os.path.exists(os.path.dirname(self.settle_log_path)):
                os.makedirs(os.path.dirname(self.settle_log_path))
            with open(self.settle_log_path, 'a') as f:
                self.settle_log_writer = BufferedWriter(FileWriter(f, True))
            return True
        except Exception as e:
            self.logger.error("meet error when creating settle log, file path: %s", self.settle_log_path)
            return False

    def write_settle_log(self, content):
        with self._lock:
            try:
                if not isinstance(content, str):
                    raise TypeError('content must be a string')
                self.settle_log_writer.write(str(content))
                self.settle_log_writer.newLine()
                self.settle_log_writer.flush()
                return True
            except Exception as e:
                self.logger.error("write settle log file failed, the log file: %s", self.settle_log_path)
                return False

    def close_log_writer(self):
        try:
            if self.settle_log_writer is not None:
                self.settle_log_writer.close()
        except Exception as e:
            self.logger.error("close upgrade log file failed, the log file: %s", self.settle_log_path)

    @property
    def settle_log_name(self):
        return os.path.basename(self.settle_log_path)


class SettleCheckStatus:
    BEGIN_SETTLE_FILE = 1
    AFTER_SETTLE_FILE = 2
    SETTLE_SUCCESS = 3

    def __init__(self, check_status):
        self.check_status = check_status

    @property
    def check_status(self):
        return self.check_status

    def __str__(self):
        return str(self.check_status)
```

Please note that Python does not have direct equivalent of Java's `Logger` and `IoTDBConfig`. You may need to implement these classes or use existing ones in your program.