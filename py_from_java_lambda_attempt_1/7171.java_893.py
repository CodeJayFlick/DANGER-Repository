Here's a translation of the Java code into equivalent Python:

```Python
class OatDexFile:
    PREFIX = "OATDEXFILE"

    def __init__(self):
        pass

    def get_dex_file_location(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_dex_file_checksum(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_dex_file_offset(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_dex_header(self) -> object:  # DexHeader equivalent
        raise NotImplementedError("Subclasses must implement this method")

    def markup(self, oat_header: object, program: object, monitor: object, log: object):
        raise NotImplementedError("Subclasses must implement this method")

    def is_dex_header_external(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I've used Python's `->` syntax to indicate the return type of each method.