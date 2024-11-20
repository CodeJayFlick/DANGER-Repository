import threading

class TsFileLock:
    def __init__(self):
        self.read_cnt = 0
        self.write_cnt = 0
        self.lock = threading.Lock()

    def read_lock(self):
        with self.lock:
            while self.write_cnt > 0:
                try:
                    self.lock.wait(1)
                except Exception as e:
                    if isinstance(e, KeyboardInterrupt):  # Re-raise the exception to propagate it up
                        raise
                    else:  # Ignore other exceptions (like InterruptedError) and continue waiting
            self.read_cnt += 1

    def read_unlock(self):
        with self.lock:
            if self.read_cnt > 0:
                self.read_cnt -= 1
                self.lock.notify_all()

    def write_lock(self):
        with self.lock:
            while self.write_cnt > 0 or self.read_cnt > 0:
                try:
                    self.lock.wait(1)
                except Exception as e:
                    if isinstance(e, KeyboardInterrupt):  # Re-raise the exception to propagate it up
                        raise
                    else:  # Ignore other exceptions (like InterruptedError) and continue waiting
            self.write_cnt += 1

    def write_unlock(self):
        with self.lock:
            if self.write_cnt > 0:
                self.write_cnt -= 1
                self.lock.notify_all()

    def try_write_lock(self):
        with self.lock:
            if self.write_cnt > 0 or self.read_cnt > 0:
                return False
            else:
                self.write_cnt += 1
                return True

    def try_read_lock(self):
        with self.lock:
            if self.write_cnt > 0:
                return False
            else:
                self.read_cnt += 1
                return True
