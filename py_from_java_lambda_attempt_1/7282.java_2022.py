Here is the translation of the given Java code into equivalent Python:

```Python
class Ext4DxRoot:
    def __init__(self, provider):
        self.dot_inode = int.from_bytes(provider.readNext(4), 'little')
        self.dot_rec_len = int.from_bytes(provider.readNext(2), 'little')
        self.dot_name_len = provider.readNext()
        self.dot_file_type = provider.readNext()
        self.dot_name = provider.readNextBytes(4)
        self.dotdot_inode = int.from_bytes(provider.readNext(4), 'little')
        self.dotdot_rec_len = int.from_bytes(provider.readNext(2), 'little')
        self.dotdot_name_len = provider.readNext()
        self.dotdot_file_type = provider.readNext()
        self.dotdot_name = provider.readNextBytes(4)
        self.dx_root_info_reserved_zero = int.from_bytes(provider.readNext(4), 'little')
        self.dx_root_info_hash_version = provider.readNext()
        self.dx_root_info_info_length = provider.readNext()
        self.dx_root_info_indirect_levels = provider.readNext()
        self.dx_root_info_unused_flags = provider.readNext()
        self.limit = int.from_bytes(provider.readNext(2), 'little')
        self.count = int.from_bytes(provider.readNext(2), 'little')
        self.block = int.from_bytes(provider.readNext(4), 'little')
        self.entries = [Ext4DxEntry(provider) for _ in range(self.count)]

    def get_dot_inode(self):
        return self.dot_inode

    def get_dot_rec_len(self):
        return self.dot_rec_len

    def get_dot_name_len(self):
        return self.dot_name_len

    def get_dot_file_type(self):
        return self.dot_file_type

    def get_dot_name(self):
        return self.dot_name

    def get_dotdot_inode(self):
        return self.dotdot_inode

    def get_dotdot_rec_len(self):
        return self.dotdot_rec_len

    def get_dotdot_name_len(self):
        return self.dotdot_name_len

    def get_dotdot_file_type(self):
        return self.dotdot_file_type

    def get_dotdot_name(self):
        return self.dotdot_name

    def get_dx_root_info_reserved_zero(self):
        return self.dx_root_info_reserved_zero

    def get_dx_root_info_hash_version(self):
        return self.dx_root_info_hash_version

    def get_dx_root_info_info_length(self):
        return self.dx_root_info_info_length

    def get_dx_root_info_indirect_levels(self):
        return self.dx_root_info_indirect_levels

    def get_dx_root_info_unused_flags(self):
        return self.dx_root_info_unused_flags

    def get_limit(self):
        return self.limit

    def get_count(self):
        return self.count

    def get_block(self):
        return self.block

    def get_entries(self):
        return self.entries


class Ext4DxEntry:
    def __init__(self, provider):
        self.inode = int.from_bytes(provider.readNext(4), 'little')
        self.rec_len = int.from_bytes(provider.readNext(2), 'little')
        self.name_len = provider.readNext()
        self.file_type = provider.readNext()
        self.name = provider.readNextBytes(self.name_len)
```

Note: The above Python code assumes that the `ByteProvider` class is equivalent to a file-like object in Python, and it can be used to read bytes from the file.