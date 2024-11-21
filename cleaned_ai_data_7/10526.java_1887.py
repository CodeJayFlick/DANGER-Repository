import io

class MonitoredInputStream(io.IOBase):
    def __init__(self, in_stream: io.IOBase, monitor):
        self.in = in_stream
        self.monitor = monitor
        self.small_count = 0
        self.count = 0

    def set_progress(self, count):
        self.count = count

    def read(self) -> int:
        if self.monitor.is_cancelled():
            raise io.IOCancelledException()
        n = self.in.read()
        if n != -1:
            self.small_count += 1
            if self.small_count >= 32768:  # PROGRESS_INCREMENT in Java is 32 * 1024
                self.count += self.small_count
                self.small_count = 0
                self.monitor.set_progress(self.count)
        return n

    def read(self, b: bytes) -> int:
        return self.read(b, 0, len(b))

    def read(self, b: bytes, off: int, len: int) -> int:
        if self.monitor.is_cancelled():
            raise io.IOCancelledException()
        n = self.in.read(b, off, len)
        self.small_count += n
        if self.small_count >= 32768:
            self.count += self.small_count
            self.small_count = 0
            self.monitor.set_progress(self.count)
        return n

    def skip(self, n: int) -> int:
        return self.in.skip(n)

    def available(self) -> int:
        return self.in.available()

    def close(self):
        self.in.close()

    def mark(self, readlimit: int):
        self.in.mark(readlimit)

    def reset(self):
        self.in.reset()

    def mark_supported(self) -> bool:
        return self.in.mark_supported()
