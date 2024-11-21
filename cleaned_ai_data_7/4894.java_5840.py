class RelocationImportedName:
    def __init__(self, reader):
        self.index = reader.read_next_short()
        self.offset = reader.read_next_short()

    @property
    def index(self):
        return self._index

    @property
    def offset(self):
        return self._offset


def read_next_short(reader):
    # assume this function reads a short integer from the input stream
    pass  # implement me!
