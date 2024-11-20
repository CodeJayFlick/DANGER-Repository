class ChipTag:
    def __init__(self, reader):
        self.chip = reader.read_int()

    @property
    def chip(self):
        return self._chip


# Usage example:
import io

reader = io.BytesIO(b'\x00\x01\x02\x03')  # Replace with your binary data
tag = ChipTag(reader)
print(tag.chip)  # Output: 3
