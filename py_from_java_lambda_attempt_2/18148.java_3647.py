Here is the translation of the Java code into Python:

```Python
class GorillaEncoderV1:
    def __init__(self):
        self.flag = False
        self.leading_zero_num = 0
        self.tailing_zero_num = 0
        self.buffer = 0x00
        self.number_left_in_buffer = 0

    def write_bit(self, b: bool, out=None) -> None:
        if not isinstance(out, bytearray):
            raise ValueError("out must be a bytearray")
        
        # add bit to buffer
        self.buffer <<= 1
        if b:
            self.buffer |= 1
        
        # if buffer is full (8 bits), write out as a single byte
        self.number_left_in_buffer += 1
        if self.number_left_in_buffer == 8:
            self.clear_buffer(out)

    def write_bit(self, i: int, out=None) -> None:
        self.write_bit(i != 0, out)

    def write_bit(self, i: long, out=None) -> None:
        self.write_bit(i != 0, out)

    def clear_buffer(self, out=None) -> None:
        if not isinstance(out, bytearray):
            raise ValueError("out must be a bytearray")
        
        if self.number_left_in_buffer == 0:
            return
        
        if self.number_left_in_buffer > 0:
            self.buffer <<= (8 - self.number_left_in_buffer)
        
        out.append(self.buffer & 0xFF)  # write the buffer as a single byte
        self.number_left_in_buffer = 0
        self.buffer = 0x00

    def reset(self):
        self.flag = False
        self.number_left_in_buffer = 0
        self.buffer = 0x00
```

Please note that Python does not have an exact equivalent of Java's `ByteArrayOutputStream`. Instead, we use the built-in list and bytearray types to simulate a byte array.