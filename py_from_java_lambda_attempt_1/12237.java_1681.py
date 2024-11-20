Here is the translation of the Java interface into Python:

```Python
class BitFieldPacking:
    def __init__(self):
        pass

    def use_ms_convention(self) -> bool:
        """Control if the alignment and packing of bit-fields follows MSVC conventions."""
        return True  # Replace with your implementation

    def is_type_alignment_enabled(self) -> bool:
        """Control whether the alignment of bit-field types is respected when laying out structures."""
        return False  # Replace with your implementation

    def get_zero_length_boundary(self) -> int:
        """A non-zero value indicates the fixed alignment size for bit-fields which follow a zero-length bitfield if greater than a bitfields base type normal alignment."""
        return 0  # Replace with your implementation
```

Note that I've used Python's built-in `bool` and `int` types to represent the Java interface methods. In Python, you don't need to explicitly define an interface or abstract class like in Java; instead, you can simply create a regular class with method definitions.