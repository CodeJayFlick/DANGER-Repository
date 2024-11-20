Here is the translation of the given Java code into Python:

```Python
class Ext4IBlock:
    def __init__(self, provider: bytes, is_extent_tree: bool) -> None:
        self.header = None
        self.index_entries = []
        self.extent_entries = []
        self.extra = b''

        self.is_extent_tree = is_extent_tree

    @classmethod
    def read_iblock_with_extents(cls, provider: bytes, offset: int) -> 'Ext4IBlock':
        reader = BinaryReader(provider)
        reader.set_pointer_index(offset)
        return cls(reader, True)

    def __init__(self, reader: 'BinaryReader', is_extent_tree: bool) -> None:
        self.is_extent_tree = is_extent_tree
        count = 0

        if self.is_extent_tree:
            self.header = Ext4ExtentHeader(reader)
            count += 1
            num_entries = self.header.eh_entries()
            is_idx_entries = self.header.eh_depth() > 0
            if is_idx_entries:
                self.index_entries = [Ext4ExtentIdx(reader) for _ in range(num_entries)]
            else:
                self.extent_entries = [Ext4Extent(reader) for _ in range(num_entries)]

        extra_bytes = 60 - (count * 12)
        if extra_bytes > 0:
            self.extra = reader.read_next_byte_array(extra_bytes)
        else:
            self.extra = b''

    @property
    def header(self):
        return self._header

    @header.setter
    def header(self, value: 'Ext4ExtentHeader'):
        self._header = value

    @property
    def index_entries(self):
        if not self._index_entries:
            return []
        return self._index_entries

    @index_entries.setter
    def index_entries(self, value: list['Ext4ExtentIdx']):
        self._index_entries = value

    @property
    def extent_entries(self):
        if not self._extent_entries:
            return []
        return self._extent_entries

    @extent_entries.setter
    def extent_entries(self, value: list['Ext4Extent']):
        self._extent_entries = value

    @property
    def extra(self) -> bytes:
        return self._extra

    @extra.setter
    def extra(self, value: bytes):
        self._extra = value


class BinaryReader:
    def __init__(self, provider: bytes) -> None:
        self.provider = provider
        self.pointer_index = 0

    def set_pointer_index(self, offset: int) -> None:
        self.pointer_index = offset

    def read_next_byte_array(self, size: int) -> bytes:
        return self.provider[self.pointer_index:self.pointer_index + size]
```

Please note that this is a direct translation of the given Java code into Python. The provided Java code seems to be part of an Ext4 file format parser for Ghidra, and it may not work as-is in a pure-Python environment without additional libraries or modifications.