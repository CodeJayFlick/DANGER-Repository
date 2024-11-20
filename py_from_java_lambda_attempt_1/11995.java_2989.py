Here is the translation of the Java code into Python:

```Python
from abc import ABC, abstractmethod


class SubMemoryBlock(ABC):
    def __init__(self, adapter: 'MemoryMapDBAdapter', record: DBRecord) -> None:
        self.adapter = adapter
        self.record = record
        self.sub_block_offset = record.get_long_value('SUB_START_OFFSET_COL')
        self.sub_block_length = record.get_long_value('SUB_LENGTH_COL')

    @abstractmethod
    def is_initialized(self) -> bool:
        pass

    @property
    def parent_block_id(self) -> int:
        return record.get_long_value('SUB_PARENT_ID_COL')

    @property
    def starting_offset(self) -> int:
        return self.sub_block_offset

    @property
    def length(self) -> int:
        return self.sub_block_length

    def contains(self, mem_block_offset: int) -> bool:
        return (mem_block_offset >= self.starting_offset and 
                mem_block_offset < self.starting_offset + self.length)

    @abstractmethod
    def get_byte(self, mem_block_offset: int) -> bytes:
        pass

    @abstractmethod
    def get_bytes(self, mem_block_offset: int, b: bytearray, off: int, len: int) -> int:
        pass

    @abstractmethod
    def put_byte(self, mem_block_offset: int, b: bytes) -> None:
        pass

    @abstractmethod
    def put_bytes(self, mem_block_offset: int, b: bytearray, off: int, len: int) -> int:
        pass

    def delete(self) -> None:
        self.adapter.delete_sub_block(record.key)

    def set_length(self, length: int) -> None:
        self.sub_block_length = length
        record.set_long_value('SUB_LENGTH_COL', length)
        self.adapter.update_sub_block_record(record)

    @abstractmethod
    def join(self, other: 'SubMemoryBlock') -> bool:
        pass

    def is_mapped(self) -> bool:
        return False

    def get_type(self) -> str:
        return 'DEFAULT'

    def get_source_info(self, block: 'MemoryBlock') -> 'MemoryBlockSourceInfo':
        return MemoryBlockSourceInfoDB(block, self)

    @abstractmethod
    def split(self, mem_block_offset: int) -> 'SubMemoryBlock':
        pass

    def set_parent_id_and_starting_offset(self, key: int, starting_offset: int) -> None:
        self.sub_block_offset = starting_offset
        record.set_long_value('SUB_PARENT_ID_COL', key)
        record.set_long_value('SUB_START_OFFSET_COL', starting_offset)
        self.adapter.update_sub_block_record(record)

    @abstractmethod
    def get_description(self) -> str:
        pass

    def uses(self, file_bytes: 'FileBytes') -> bool:
        return False

    def __lt__(self, other):
        if not isinstance(other, SubMemoryBlock):
            raise TypeError('Only a SubMemoryBlock can be compared with this one')
        return self.starting_offset < other.starting_offset
```

Please note that Python does not have direct equivalent of Java's abstract classes and methods. Instead, we use the ABC (Abstract Base Classes) module to create an abstract class in Python.