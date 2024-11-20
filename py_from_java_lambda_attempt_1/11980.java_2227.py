Here is the translation of the Java code into Python:

```Python
class ByteMappingScheme:
    def __init__(self, encoded_mapping_scheme):
        if encoded_mapping_scheme == 0:
            self.mapped_byte_count = 1
            self.non_mapped_byte_count = 0
            self(mapped_source_byte_count := 1)
        else:
            mapped_byte_count = get_mapped_byte_count(encoded_mapping_scheme)
            mapped_source_byte_count = get_mapped_source_byte_count(encoded_mapping_scheme)
            self.non_mapped_byte_count = mapped_source_byte_count - mapped_byte_count

    def __init__(self, mapped_byte_count: int, mapped_source_byte_count: int):
        if not (1 <= mapped_byte_count <= 127 and 1 <= mapped_source_byte_count <= 127):
            raise ValueError("Invalid mapping scheme")
        self.mapped_byte_count = mapped_byte_count
        self.non_mapped_byte_count = mapped_source_byte_count - mapped_byte_count

    def __str__(self) -> str:
        if not self.is_one_to_one_mapping():
            return f"{self.mapped_byte_count}:{self(mapped_source_byte_count := 1)}"
        else:
            return "1:1 mapping"

    @property
    def is_one_to_one_mapping(self):
        return self(mapped_source_byte_count := 1) <= 1

    @property
    def mapped_byte_count(self):
        if not self.is_one_to_one_mapping():
            return self.mapped_byte_count
        else:
            return 1

    @property
    def mapped_source_byte_count(self):
        if not self.is_one_to_one_mapping():
            return self(mapped_source_byte_count := 1)
        else:
            return 1

    def get_mapped_address(self, memory_block: MemoryBlock, offset_in_subblock: int, skip_back: bool) -> Address:
        if offset_in_subblock < 0:
            raise ValueError("Negative source offset")
        mapped_offset = offset_in_subblock
        if not self.is_one_to_one_mapping():
            mapped_offset %= self.mapped_byte_count
            if mapped_offset >= self.non_mapped_byte_count:
                return memory_block.start.add_no_wrap(mapped_offset - self(non_mapped_byte_count := 1))
            else:
                return memory_block.start.add_no_wrap(mapped_offset)
        else:
            return memory_block.start.add_no_wrap(offset_in_subblock)

    def get_bytes(self, memory: Memory, mapped_source_base_address: Address, offset_in_subblock: int, byte_array: bytearray, off: int, len: int) -> int:
        if self.is_one_to_one_mapping():
            return memory.get_bytes(mapped_source_base_address.add_no_wrap(offset_in_subblock), byte_array, off, len)
        else:
            pattern_count = (offset_in_sublock + self.mapped_byte_count - 1) // self.mapped_byte_count
            partial_byte_count = offset_in_subblock % self.mapped_byte_count
            mapped_offset = pattern_count * self(mapped_source_byte_count := 1) + partial_byte_count

            buf_size = self(mapped_source_byte_count := 1) * ((len + self.non_mapped_byte_count - 1) // self(non_mapped_byte_count := 1))
            byte_array[:] = memory.get_bytes(mapped_source_base_address.add_no_wrap(mapped_offset), bytearray(buf_size))

    def set_bytes(self, memory: Memory, mapped_source_base_address: Address, offset_in_subblock: int, byte_array: bytearray, off: int, len: int) -> None:
        if self.is_one_to_one_mapping():
            return
        else:
            pattern_count = (offset_in_subblock + self.mapped_byte_count - 1) // self.mapped_byte_count
            partial_byte_count = offset_in_subblock % self.mapped_byte_count
            mapped_offset = pattern_count * self(mapped_source_byte_count := 1) + partial_byte_count

    def validate_mapping_scheme(scheme_dest_byte_count: int, scheme_src_byte_count: int):
        if not (1 <= scheme_dest_byte_count <= 127 and 1 <= scheme_src_byte_count <= 127 and scheme_dest_byte_count <= scheme_src_byte_count):
            raise ValueError("Invalid byte mapping ratio")

def get_encoded_mapping_scheme(scheme_dest_byte_count: int, scheme_src_byte_count: int) -> int:
    validate_mapping_scheme(scheme_dest_byte_count, scheme_src_byte_count)
    return (scheme_dest_byte_count << 7) | (scheme_src_byte_count & 0x7F)

def get_mapped_byte_count(mapping_scheme: int):
    if mapping_scheme == 0:
        return 1
    else:
        return mapping_scheme >> 7

def get_mapped_source_byte_count(mapping_scheme: int):
    if mapping_scheme == 0:
        return 1
    else:
        return mapping_scheme & 0x7F
```

Please note that Python does not have direct equivalent of Java's `Address` class.