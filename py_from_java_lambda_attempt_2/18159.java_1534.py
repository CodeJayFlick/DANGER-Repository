Here is the translation of the Java code to Python:
```python
class SinglePrecisionEncoderV2:
    def encode(self, value: float, out):
        self.encode(Float.floatToRawIntBits(value), out)

    def flush(self, out):
        # ending stream
        self.encode(0x7F800000, out)  # GORILLA_ENCODING_ENDING_FLOAT

        # flip the byte no matter it is empty or not
        # the empty ending byte is necessary when decoding
        self.bits_left = 0
        self.flip_byte(out)

        # the encoder may be reused, so let us reset it
        self.reset()

    def __init__(self):
        pass

# Note: The following Python code does NOT exactly replicate the Java code.
# It's a translation of the logic into Python. You might need to adjust it based on your specific requirements.

class IntGorillaEncoder:
    def encode(self, value: int, out):
        # TO DO: implement this method
        pass

    def flush(self, out):
        # TO DO: implement this method
        pass

    def reset(self):
        # TO DO: implement this method
        pass

    def flip_byte(self, out):
        # TO DO: implement this method
        pass

    def __init__(self):
        self.bits_left = 0
```
Note that I did not translate the `IntGorillaEncoder` class in its entirety, as it seems to be a custom implementation specific to the original Java code. You will need to fill in the missing methods (`encode`, `flush`, and others) based on your requirements.

Also, Python does not have an exact equivalent of Java's `ByteArrayOutputStream`. Instead, you can use the built-in `bytes` type or libraries like `io.BytesIO` if needed.