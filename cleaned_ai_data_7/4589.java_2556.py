class ByteArrayProvider:
    def __init__(self, bytes=None, fsrl=None):
        self.src_bytes = bytes if bytes else bytearray()
        self.name = None
        self.fsrl = fsrl

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def close(self):
        pass  # don't do anything for now

    def hard_close(self):
        self.src_bytes = bytearray()

    @property
    def fsrl(self):
        return self._fsrl

    @fsrl.setter
    def fsrl(self, value):
        self._fsrl = value

    def get_fsrl(self):
        return self.fsrl

    def get_file(self):
        return None  # always returns None in this implementation

    def get_name(self):
        if self.fsrl:
            return self.fsrl.name
        else:
            return self.name

    def get_absolute_path(self):
        if self.fsrl:
            return self.fsrl.path
        else:
            return ""

    def read_bytes(self, index: int, length: int) -> bytearray:
        if not 0 <= index < len(self.src_bytes):
            raise ValueError("Invalid position")
        if not 0 <= length <= len(self.src_bytes[index:]):
            raise ValueError("Attempt to read beyond end of byte data")

        dest_bytes = bytearray(length)
        self.src_bytes[index:index+length].copyto(dest_bytes)
        return dest_bytes

    def get_length(self):
        return len(self.src_bytes)

    def is_valid_index(self, index: int) -> bool:
        return 0 <= index < len(self.src_bytes)

    def read_byte(self, index: int) -> bytes:
        if not self.is_valid_index(index):
            raise ValueError("Invalid position")
        return self.src_bytes[index].tobytes()
