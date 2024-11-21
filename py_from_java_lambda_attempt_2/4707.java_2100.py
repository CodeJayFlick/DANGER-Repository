Here is the translation of the Java code to Python:
```
import io

class NullSectionProvider:
    def __init__(self):
        pass

    def get_section_as_byte_provider(self, section_name: str) -> bytes:
        return b''

    def has_section(self, *section_names: str) -> bool:
        return True

    def close(self):
        pass
```
Note that I've used the `io` module to create an empty byte string (`b''`) in the `get_section_as_byte_provider` method. In Python, strings are Unicode by default, so we don't need to worry about encoding issues like we would with Java's `ByteProvider`.