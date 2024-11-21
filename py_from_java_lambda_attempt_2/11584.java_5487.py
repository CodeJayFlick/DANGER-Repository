Here is the translation of the given Java interface into a Python class:

```Python
class LoadImage:
    def load_fill(self, buffer: bytes, size: int, address: str, buf_offset: int, generate_initialized_mask: bool) -> bytes | None:
        pass  # TODO implement this method


# Example usage:
load_image = LoadImage()
buffer = b'example'
size = 10
address = '0x12345678'
buf_offset = 5

result = load_image.load_fill(buffer, size, address, buf_offset, True)
print(result)  # prints the result of calling the method
```

Please note that this is a direct translation and does not include any actual implementation for the `load_fill` method. The method signature remains the same as in Java, with some minor adjustments to accommodate Python's syntax differences.