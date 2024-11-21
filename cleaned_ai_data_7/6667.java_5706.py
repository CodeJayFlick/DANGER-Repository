class ByteSequenceLengthFilter:
    def __init__(self, internal_index: int, min_length: int):
        if min_length < 0:
            raise ValueError("min_length must be non-negative!")
        if min_length < abs(internal_index):
            raise ValueError("min_length too small for this internal_index!")

        self.internal_index = internal_index * 2
        self.min_length = min_length * 2

    def filter(self, base: str) -> str:
        if not base or len(base) < self.min_length:
            return None
        if self.internal_index >= 0:
            return base[:self.internal_index]
        length = len(base)
        return base[length + self.internal_index:length]

    def __str__(self):
        sb = f"internalIndex: {self.internal_index}\nminLength: {self.min_length}\n"
        return sb
