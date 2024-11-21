class EmptyByteProvider:
    def __init__(self):
        self.fsrl = None

    def get_fsrl(self):
        return self.fsrl

    def get_file(self):
        return None

    def get_name(self):
        if self.fsrl is not None:
            return self.fsrl.name
        else:
            return None

    def get_absolute_path(self):
        if self.fsrl is not None:
            return self.fsrl.path
        else:
            return None

    def read_byte(self, index):
        raise IOError("Not supported")

    def read_bytes(self, index, length):
        if index != 0 or length != 0:
            raise IOError("Not supported")
        return bytearray()

    def get_length(self):
        return 0

    def is_valid_index(self, index):
        return False

    def close(self):
        pass

    def get_input_stream(self, index):
        if index != 0:
            raise IOError("Invalid offset")
        return None
