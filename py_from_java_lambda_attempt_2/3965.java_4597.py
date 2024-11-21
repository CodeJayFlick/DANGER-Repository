Here is the translation of the Java code into Python:

```Python
class MaskContainer:
    def __init__(self, mask: bytes, value: bytes):
        if not (mask and value):  # Check for null values
            raise ValueError("Mask container initialization error: mask and/or value arrays cannot be None")
        
        if len(mask) != len(value):
            raise ValueError("Mask container initialization error: mask/value arrays must be the same size")

        self.mask = mask
        self.value = value

    def get_mask(self) -> bytes:
        return self.mask

    def get_value(self) -> bytes:
        return self.value

    def set_mask(self, mask: bytes):
        self.mask = mask

    def set_value(self, value: bytes):
        self.value = value

    def to_binary_string(self) -> str:
        value_str = ''.join(format(b, '08b') for b in self.value)
        mask_str = ''.join(format(b, '08b') for b in self.mask)

        return f"{value_str} {mask_str}"
```

Note that Python does not have a direct equivalent to Java's `byte[]` type. Instead, we use the built-in `bytes` type to represent arrays of bytes. The `format()` function is used to convert each byte into its binary representation as a string.