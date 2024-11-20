Here is the equivalent Python code:

```Python
class MetadataIndexEntry:
    def __init__(self, name: str, offset: int):
        self.name = name
        self.offset = offset

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def offset(self) -> int:
        return self._offset

    @offset.setter
    def offset(self, value: int):
        self._offset = value

    def __str__(self) -> str:
        return f"<{self.name},{self.offset}>"

def serialize_to(output_stream, metadata_index_entry: MetadataIndexEntry) -> int:
    byte_len = 0
    byte_len += len(metadata_index_entry.name).to_bytes(4, 'little') + metadata_index_entry.name.encode('utf-8')
    byte_len += metadata_index_entry.offset.to_bytes(8, 'little')
    return byte_len

def deserialize_from(buffer: bytes) -> MetadataIndexEntry:
    buffer.seek(0)
    name_length = int.from_bytes(buffer.read(4), 'little')
    name = buffer.read(name_length).decode('utf-8')
    offset = int.from_bytes(buffer.read(8), 'little')
    return MetadataIndexEntry(name, offset)

# Example usage
metadata_index_entry = MetadataIndexEntry("example_name", 1234567890)
output_stream = open("test.bin", "wb")
serialized_len = serialize_to(output_stream, metadata_index_entry)
print(f"Serialized length: {serialized_len}")
output_stream.close()

buffer = open("test.bin", "rb").read()
deserialized_metadata_index_entry = deserialize_from(buffer)
print(deserialized_metadata_index_entry)
```

This Python code defines a `MetadataIndexEntry` class with similar attributes and methods as the Java original. The `serialize_to` function serializes an instance of this class to bytes, which can be written to a file or network stream. The `deserialize_from` function reads serialized data from a buffer (which could represent a file or network stream) and returns a new `MetadataIndexEntry` object.

Please note that Python's built-in serialization mechanisms are different from Java's, so the code is not identical but equivalent in functionality.