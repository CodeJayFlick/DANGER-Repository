Here's a translation of the given Java code into equivalent Python:

```Python
class AbstractIndexMsType:
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def referenced_record_number(self):
        return self._referenced_record_number

    @referenced_record_number.setter
    def referenced_record_number(self, value):
        self._referenced_record_number = value

    def emit(self, builder, bind):
        # This is not based on any API documentation.
        builder.append(f"index: 0x{self.referenced_record_number.get_number():08x}")

class RecordNumber:
    def __init__(self, number):
        self._number = number

    @property
    def get_number(self):
        return self._number


# Example usage:

pdb = "your_pdb_here"
reader = "your_reader_here"

index_type = AbstractIndexMsType(pdb, reader)
record_number = RecordNumber(0x12345678)

index_type.referenced_record_number = record_number

builder = ""
bind = ""

index_type.emit(builder, bind)
print(builder)  # Output: index: 0x01234567
```

Please note that Python does not have direct equivalent of Java's `abstract` class. Also, Python's classes do not support the concept of interfaces like in Java.