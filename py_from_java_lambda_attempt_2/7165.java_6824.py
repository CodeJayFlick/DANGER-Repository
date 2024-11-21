Here is the translation of the Java code to Python:
```
import struct

class MethodBssMappingEntry:
    def __init__(self):
        self.method_index = 0
        self.index_mask = 0
        self.bss_offset = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> 'MethodBssMappingEntry':
        method_index, index_mask, bss_offset = struct.unpack('<HHi', data)
        return cls(method_index, index_mask, bss_offset)

    def __init__(self, method_index: int, index_mask: int, bss_offset: int):
        self.method_index = method_index
        self.index_mask = index_mask
        self.bss_offset = bss_offset

    @property
    def method_index(self) -> int:
        return self._method_index

    @method_index.setter
    def method_index(self, value: int):
        self._method_index = value

    @property
    def index_mask(self) -> int:
        return self._index_mask

    @index_mask.setter
    def index_mask(self, value: int):
        self._index_mask = value

    @property
    def bss_offset(self) -> int:
        return self._bss_offset

    @bss_offset.setter
    def bss_offset(self, value: int):
        self._bss_offset = value
```
Note that I did not include the `toDataType` method as it is specific to Java's StructConverter interface and does not have a direct equivalent in Python.