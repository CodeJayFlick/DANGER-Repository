Here is the translation of the Java code into Python:

```Python
class DecmpfsHeader:
    def __init__(self, reader):
        self.compression_magic = reader.read_int()
        original_endian = reader.is_little_endian()
        reader.set_little_endian(True)
        self.compression_type = reader.read_int()
        self.uncompressed_size = reader.read_long()

        if (reader.get_pointer_index() + 8 % 2) != 0:
            reader.seek(reader.get_pointer_index() - 1)

        n_elements = int((reader.get_pointer_index() + 8) / 2)
        if (n_elements % 2) != 0:
            n_elements += 1
        elif n_elements < 0:
            print("here")
        self.attr_bytes = reader.read_bytes(n_elements)

    def get_compression_magic(self):
        return str(self.compression_magic)

    def get_compression_type(self):
        return self.compression_type

    def get_uncompressed_size(self):
        return self.uncompressed_size

    def get_attr_bytes(self):
        return self.attr_bytes
```

Note that Python does not have direct equivalents for Java's `GBinaryReader`, `GStringUtilities` and other classes. The above code assumes a custom reader class with methods like `read_int()`, `is_little_endian()` and others, which are used to read binary data from some source (e.g., file or network stream).