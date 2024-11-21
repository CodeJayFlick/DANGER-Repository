Here is the translation of the given Java code into Python:

```Python
class FileBytesAdapter:
    MAX_BUF_SIZE = 1000000000
    
    FILENAME_COL = 'FILENAME_ COL'
    OFFSET_COL = 'OFFSET_ COL'
    SIZE_COL = 'SIZE_ COL'
    BUF_IDS_COL = 'BUF_IDS_ COL'
    LAYERED_BUF_IDS_COL = 'LAYERED_BUF_IDS_ COL'

    def __init__(self, handle):
        self.handle = handle

class FileBytesAdapterV0(FileBytesAdapter):
    pass

def get_adapter(handle, open_mode, monitor=None):
    if open_mode == "CREATE":
        return FileBytesAdapterV0(handle, True)
    try:
        return FileBytesAdapterV0(handle, False)
    except VersionException as e:
        if not e.is_upgradable() or open_mode == "UPDATE":
            raise
        adapter = find_read_only_adapter(handle)
        if open_mode == "UPGRADE":
            adapter = upgrade(handle, adapter, monitor)
        return adapter

def find_read_only_adapter(handle):
    return FileBytesAdapterV0(handle)

def upgrade(handle, old_adapter, monitor=None):
    return FileBytesAdapterV0(handle, True)

class DBBuffer:
    def __init__(self, buffer_id):
        self.buffer_id = buffer_id

class MemoryMapDB:
    pass

class FileBytes:
    def __init__(self, filename, offset, size, is_):
        self.filename = filename
        self.offset = offset
        self.size = size
        self.is = is_

def create_file_bytes(self, filename, offset, size, is_) -> 'FileBytes':
    pass

class FileBytesAdapterNoTable(FileBytesAdapter):
    def __init__(self, handle):
        super().__init__(handle)

    def get_buffer(self, buffer_id) -> DBBuffer:
        if buffer_id >= 0:
            return self.handle.get_buffer(buffer_id)
        return None

def get_buffer(self, buffer_id: int, shadow_buffer: 'DBBuffer') -> 'DBBuffer':
    if buffer_id >= 0:
        return self.handle.get_buffer(buffer_id, shadow_buffer)
    return None

@classmethod
def get_max_buffer_size(cls):
    return cls.MAX_BUF_SIZE

# *** FOR TESTING PURPOSES ONLY ***
@classmethod
def set_max_buffer_size(cls, test_size: int):
    cls.MAX_BUF_SIZE = test_size

class List:
    pass

abstract methods:

- getAllFileBytes(self) -> 'List[FileBytes]'
- refresh(self)
- delete_file_bytes(self, file_bytes: FileBytes)

```

Please note that this is a direct translation of the given Java code into Python. However, it may not be entirely correct or idiomatic in terms of Pythonic coding practices and conventions.