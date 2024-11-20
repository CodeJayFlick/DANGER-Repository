class MonitoredOutputStream:
    def __init__(self, out, monitor):
        self.out = out
        self.monitor = monitor
        self.small_count = 0
        self.count = 0

    def write(self, b: int) -> None:
        self.out.write(b)
        self.small_count += 1
        if self.small_count >= 32768:  # equivalent to PROGRESS_INCREMENT in Java
            if self.monitor.is_cancelled():
                raise IOCancelledException()
            self.count += self.small_count
            self.small_count = 0
            self.monitor.set_progress(self.count)

    def write(self, b: bytes) -> None:
        self.write(b, 0, len(b))

    def write(self, b: bytes, off: int, len: int) -> None:
        self.out.write(b[off:off + len])
        self.small_count += len
        if self.small_count >= 32768:  
            if self.monitor.is_cancelled():
                raise IOCancelledException()
            self.count += self.small_count
            self.small_count = 0
            self.monitor.set_progress(self.count)

    def flush(self) -> None:
        self.out.flush()

    def close(self) -> None:
        try:
            self.flush()
        except Exception as ignored:  
            pass
        finally:
            self.out.close()


class IOCancelledException(Exception):
    pass

