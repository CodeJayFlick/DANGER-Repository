Here is a translation of the Java interface into equivalent Python code:

```Python
class LldbModelTargetStackFrameRegister:
    def __init__(self):
        pass

    def get_bit_length(self) -> int:
        # This method should be implemented in your subclass.
        raise NotImplementedError("get_bit_length must be implemented")

    def get_register(self) -> bytes:
        # This method should be implemented in your subclass.
        raise NotImplementedError("get_register must be implemented")

    def get_bytes(self) -> bytearray:
        val = self.get_cached_attributes().get('VALUE_ATTRIBUTE_NAME')
        value = int(val, 16)
        return ConversionUtils.bigIntegerToBytes(16, value).tobytes()
```

Please note that this is a translation of the interface into Python and does not include any actual implementation. The `get_bit_length` and `get_register` methods are marked as abstract because they do not have an implementation in the original Java code.

Also, I've used the following classes:

- `bytes`: A built-in Python type representing a sequence of bytes.
- `bytearray`: A mutable version of the `bytes` class.