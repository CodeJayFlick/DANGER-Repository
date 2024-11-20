Here is the translation of the Java interface `ElfFileSection` to a Python class:

```python
class ElfFileSection:
    def __init__(self):
        pass

    @property
    def address_offset(self) -> int:
        """Preferred memory address offset where data should be loaded."""
        return 0  # Replace with actual implementation

    @property
    def file_offset(self) -> int:
        """Offset within file where section bytes are specified"""
        return 0  # Replace with actual implementation

    @property
    def length(self) -> int:
        """Length of file section in bytes"""
        return 0  # Replace with actual implementation

    @property
    def entry_size(self) -> int:
        """Size of each structured entry in bytes. Returns -1 if variable."""
        return -1  # Replace with actual implementation
```

Note that I've used Python's property decorator to create getter methods for the interface's methods, as there is no direct equivalent to Java interfaces in Python. The `__init__` method is empty since it doesn't seem to have any specific initialization logic.

Also, please replace the return values with actual implementation details, which would depend on your specific use case and requirements.