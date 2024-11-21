Here is the translation of the given Java code into equivalent Python:

```Python
class DyldCacheSlideInfo1:
    def __init__(self):
        self.toc_offset = None
        self.toc_count = None
        self.entries_offset = None
        self.entries_count = None
        self.entries_size = None

    @property
    def toc_offset(self):
        return self._toc_offset

    @toc_offset.setter
    def toc_offset(self, value):
        self._toc_offset = value

    @property
    def toc_count(self):
        return self._toc_count

    @toc_count.setter
    def toc_count(self, value):
        self._toc_count = value

    @property
    def entries_offset(self):
        return self._entries_offset

    @entries_offset.setter
    def entries_offset(self, value):
        self._entries_offset = value

    @property
    def entries_count(self):
        return self._entries_count

    @entries_count.setter
    def entries_count(self, value):
        self._entries_count = value

    @property
    def entries_size(self):
        return self._entries_size

    @entries_size.setter
    def entries_size(self, value):
        self._entries_size = value


class BinaryReader:
    def __init__(self, data):
        self.data = data
        self.index = 0

    def read_next_int(self):
        int_val = int.from_bytes(self.data[self.index:self.index+4], 'little')
        self.index += 4
        return int_val


def create_dyld_cache_slide_info1(reader: BinaryReader) -> DyldCacheSlideInfo1:
    dyld_cache_slide_info1 = DyldCacheSlideInfo1()
    dyld_cache_slide_info1.toc_offset = reader.read_next_int()
    dyld_cache_slide_info1.toc_count = reader.read_next_int()
    dyld_cache_slide_info1.entries_offset = reader.read_next_int()
    dyld_cache_slide_info1.entries_count = reader.read_next_int()
    dyld_cache_slide_info1.entries_size = reader.read_next_int()

    return dyld_cache_slide_info1


class DataType:
    def __init__(self, name):
        self.name = name
        self.members = []

    def add(self, member_type, member_name, description):
        self.members.append((member_type, member_name, description))

    def set_category_path(self, category_path):
        self.category_path = category_path


def to_data_type(dyld_cache_slide_info1: DyldCacheSlideInfo1) -> DataType:
    data_type = DataType("dyld_ cache_ slide_ info")
    data_type.add(DWORD, "version", "")
    data_type.add(DWORD, "toc_offset", "")
    data_type.add(DWORD, "toc_count", "")
    data_type.add(DWORD, "entries_offset", "")
    data_type.add(DWORD, "entries_count", "")
    data_type.add(DWORD, "entries_size", "")

    return data_type


class MachConstants:
    DATA_TYPE_CATEGORY = None
```

Note that Python does not have direct equivalent of Java's `package`, so I did not include it in the translation. Also, Python does not support annotations like Java, so I removed them as well.