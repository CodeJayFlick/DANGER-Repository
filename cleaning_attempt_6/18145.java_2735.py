import io.BytesIO

class DoublePrecisionEncoderV2:
    def __init__(self):
        pass  # equivalent to a no-op constructor in Java

    def encode(self, value: float, out: BytesIO) -> None:
        self.encode(Long.fromBits(Double.doubleToRawLongBits(value)).longValue(), out)

    def flush(self, out: BytesIO) -> None:
        self.encode(0x7FFFFFFFFFFFFFFF, out)  # equivalent to GORILLA_ENCODING_ENDING_DOUBLE
        bits_left = 0
        self.flip_byte(out)
        self.reset()

    def reset(self) -> None:
        pass  # equivalent to a no-op method in Java

    def flip_byte(self, out: BytesIO) -> None:
        pass  # equivalent to a no-op method in Java
