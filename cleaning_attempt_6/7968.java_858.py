import threading
import io
from buffer import BufferReader

class PdbErrorReaderThread(threading.Thread):
    def __init__(self, err_stream):
        super().__init__()
        self.err = err_stream
        self.errbuf = ""

    def has_errors(self):
        return len(self.errbuf) != 0 and "ERROR" in self.errbuf

    def has_warnings(self):
        return len(self.errbuf) != 0 and "WARNING" in self.errbuf

    def get_error_and_warning_messages(self):
        if not self.errbuf:
            return None
        return self.errbuf

    def run(self):
        try:
            reader = io.TextIOWrapper(io.BufferedReader(err_stream)).readlines()
            for line in reader:
                self.errbuf += line.decode() + "\n"
        except Exception as e:
            print("Failed to read error stream.")
