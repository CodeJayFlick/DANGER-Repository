class ROMHeader:
    def __init__(self):
        self.file_header = None
        self.optional_header = None

    @property
    def file_header(self):
        return self._file_header

    @file_header.setter
    def file_header(self, value):
        self._file_header = value

    @property
    def optional_header(self):
        return self._optional_header

    @optional_header.setter
    def optional_header(self, value):
        self._optional_header = value


class FileHeader:
    pass


class OptionalHeaderROM:
    pass
