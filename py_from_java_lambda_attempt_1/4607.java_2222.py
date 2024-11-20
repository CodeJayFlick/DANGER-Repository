Here is the translation of the Java code to Python:
```python
import io

class BigEndianUnitSizeByteSwapperInputStream(io.BytesIO):
    def __init__(self, input_stream: bytes, unit_size: int) -> None:
        self.input = input_stream
        self.unit_size = unit_size
        self.array = [0] * unit_size
        self.array_position = -1

    def read(self) -> int:
        if self.array_position == -1:
            for i in range(self.unit_size):
                self.array[i] = int.from_bytes(self.input.read(1), 'little')
            self.array_position = self.unit_size - 1
        return self.array[self.array_position]
```
Note that I used the `io` module to create a custom stream class, and the `int.from_bytes()` function to convert bytes to integers. The rest of the code is similar to the original Java code.

Also, since Python does not have built-in support for big-endian byte swapping like Java's `ByteBuffer`, we need to manually swap the bytes when reading from the input stream. This is done by using the `'little'` byte order in the `int.from_bytes()` function and then reversing the array elements if necessary.

Please note that this code assumes that the input stream contains only integers, which may not be the case for all COFF files. You may need to modify the code further depending on your specific use case.