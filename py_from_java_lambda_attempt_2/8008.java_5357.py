Here is the translation of the Java code into Python:

```Python
class MsfFileReader:
    def __init__(self, msf: 'AbstractMsf', file):
        self.msf = msf
        self.file = file

    def close(self) -> None:
        if self.file:
            self.file.close()

    def read_page(self, page: int, bytes: bytearray) -> None:
        self.read(page, 0, self.msf.get_page_size(), bytes, 0)

    def read(self, page: int, offset: int, num_to_read: int, bytes: bytearray, bytes_offset: int) -> None:
        if num_to_read < 1:
            raise IOException("Must request at least one byte in MSF read")

        if offset < 0 or offset >= self.msf.get_page_size():
            raise IOException(f"Offset must be in range [0, {self.msf.get_page_size()}) for MSF read")

        file_offset = (offset + page * self.msf.get_page_size())

        if not self.msf.is_valid_read(file_offset, num_to_read):
            raise IOException("Invalid MSF configuration")

        bytes_read = 0
        self.file.seek(file_offset)
        bytes_read = self.file.readinto(bytes[bytes_offset:bytes_offset+num_to_read])

        if bytes_read != num_to_read:
            raise IOException("Could not read required bytes from MSF")
```

Note that Python does not have a direct equivalent to Java's `AutoCloseable` interface, so I've simply added the `close()` method as part of the class. Also, in Python, we do not need to specify types for function parameters or return values like we would in Java.

The `read_page()` and `read()` methods are essentially identical to their Java counterparts, with some minor adjustments due to differences between the two languages (e.g., using `bytearray` instead of a raw byte array).