Here is the translation of the given Java code into Python:

```Python
class AlignmentDataType:
    def __init__(self):
        self.__compute_length = None

    @property
    def compute_length(self):
        if not self.__compute_length:
            self.__compute_length = 0
            try:
                start_byte = memory_buffer.getbyte(0)
                listing = None
                try:
                    if memory_buffer.memory and memory_buffer.memory.program:
                        listing = memory_buffer.memory.program.listing
                except UnsupportedOperationException:
                    pass

                while True:
                    byte_b = memory_buffer.getbyte(self.__compute_length)
                    address = memory_buffer.address + self.__compute_length
                    if listing and (listing.getdefineddataat(address) or listing.getinstructionat(address)):
                        break
                    elif byte_b != start_byte:
                        break
                    else:
                        self.__compute_length += 1

            except MemoryAccessException as e:
                pass
            except AddressOutOfBoundsException as exc:
                pass

        return -1 if not self.__compute_length else self.__compute_length


    def clone(self, dtm):
        if dtm == self.get_datatype_manager():
            return self
        return AlignmentDataType(dtm)


    @property
    def description(self):
        return "Consumes alignment/repeating bytes."


    def get_mnemonic(self, settings):
        return "align"


    def can_specify_length(self):
        return True


    def get_length(self, memory_buffer, length=-1):
        if length < 0:
            length = self.compute_length
        return length


    @property
    def representation(self):
        return lambda buf, settings, length: f"align({length})"


    def get_value(self, memory_buffer, settings, length=0):
        return self.representation(memory_buffer, settings, length)


    @property
    def value_class(self):
        from builtins import str as string_type
        return type(string_type())


    def get_length_base(self):
        return -1


    def get_replacement_base_type(self):
        from ghidra.program.model.data import ByteDataType
        return ByteDataType.dataType

# Usage:
memory_buffer = None  # Replace with your memory buffer object.
alignment_data_type = AlignmentDataType()
print(alignment_data_type.get_length(memory_buffer, alignment_data_type.compute_length))
```

Please note that Python does not support the concept of "final" in Java. The `compute_length` method is a property (a getter) because it seems to be used as such in the original code.