Here is the translation of the Java interface `ArtCompression` into a Python class:

```python
class ArtCompression:
    def __init__(self):
        pass

    def get_storage_mode(self) -> int:
        raise UnknownArtStorageModeException("Unknown storage mode")

    def get_compressed_size(self) -> int:
        return 0

    def get_compressed_offset(self) -> int:
        return 0

    def get_decompressed_size(self) -> int:
        return 0

    def get_decompressed_offset(self) -> int:
        return 0


class UnknownArtStorageModeException(Exception):
    pass
```

Note that I've created a separate `UnknownArtStorageModeException` class to match the Java exception. In Python, exceptions are typically defined as classes inheriting from the built-in `Exception` class.

Also, in Python, we don't have an exact equivalent of Java's interface concept. Instead, we can define a base class with abstract methods (i.e., methods that must be implemented by any subclass). However, since this code is primarily about defining constants and simple getter/setter methods, I've chosen to translate it into a regular Python class instead.