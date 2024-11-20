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
