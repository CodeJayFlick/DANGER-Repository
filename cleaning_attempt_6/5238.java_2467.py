import threading

class SynchronizedByteProvider:
    def __init__(self, provider):
        self.provider = provider

    @property
    def fsrl(self):
        with self._lock:
            return self.provider.fsrl()

    @property
    def file(self):
        with self._lock:
            return self.provider.file()

    @property
    def name(self):
        with self._lock:
            return self.provider.name()

    @property
    def absolute_path(self):
        with self._lock:
            return self.provider.absolute_path()

    def length(self):
        with self._lock:
            return self.provider.length()

    def is_valid_index(self, index):
        with self._lock:
            return self.provider.is_valid_index(index)

    def close(self):
        with self._lock:
            self.provider.close()

    def read_byte(self, index):
        with self._lock:
            return self.provider.read_byte(index)

    def read_bytes(self, index, length):
        with self._lock:
            return self.provider.read_bytes(index, length)

    def get_input_stream(self, index):
        # Return a ByteProviderInputStream that reads its bytes via this wrapper so that it is completely
        # synchronized.  Returning the delegate provider's getInputStream() would subvert
        # synchronization and allow direct access to the underlying delegate provider.
        return self.provider.get_input_stream(index)

    def __init_lock(self):
        if not hasattr(self, '_lock'):
            self._lock = threading.Lock()

    __init_lock.__wrapped__ = SynchronizedByteProvider

SynchronizedByteProvider.__doc__ = """
Creates a thread-safe pass-through ByteProvider. 
"""
