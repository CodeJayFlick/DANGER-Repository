Here is the translation of the given Java code into Python:

```Python
class MinLengthCharSequenceMatcher:
    def __init__(self, minimum_sequence_length: int, char_set: set[int], alignment: int):
        self.minimum_sequence_length = minimum_sequence_length
        self.char_set = char_set
        self.alignment = alignment

        self.sequence_start_index = -1
        self.current_index = -1
        self.in_ascii_sequence = False
        self.last_sequence = None

    def add_char(self, c: int) -> bool:
        if not self.in_ascii_sequence and self.meets_alignment_requirement():
            self.sequence_start_index = self.current_index
            self.in_ascii_sequence = True

        if c in self.char_set:
            pass  # do nothing
        elif c == 0:
            return self.check_sequence(self.sequence_start_index, self.current_index - 1, True)
        else:
            return self.check_sequence(self.sequence_start_index, self.current_index - 1, False)

    def meets_alignment_requirement(self) -> bool:
        return self.current_index % self.alignment == 0

    def end_sequence(self) -> bool:
        return self.check_sequence(self.sequence_start_index, self.current_index - 1, False)

    def reset(self):
        self.current_index = -1
        self.in_ascii_sequence = False
        self.last_sequence = None

    @property
    def sequence(self) -> 'Sequence':
        return self.last_sequence


class Sequence:
    def __init__(self, start: int, end: int, data_type: str, null_terminated: bool):
        self.start = start
        self.end = end
        self.data_type = data_type
        self.null_terminated = null_terminated

# Example usage:

char_set = {0x20, 0x21, 0x22}  # ASCII characters ' ', ')', '('
alignment = 4
minimum_sequence_length = 3

matcher = MinLengthCharSequenceMatcher(minimum_sequence_length, char_set, alignment)

while True:
    c = input("Enter a character (or press Enter to end): ")
    if not c:
        break
    matcher.add_char(ord(c))

print(f"Found sequence: {matcher.sequence}")
```

Please note that Python does not have an exact equivalent of Java's `CharSetRecognizer` class. In this translation, I used a set comprehension (`{0x20, 0x21, 0x22}`) to represent the character set in Python.