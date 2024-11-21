class MultiByteCharMatcher:
    def __init__(self, min_length, char_set, char_width, endian, alignment, offset):
        if offset < 0 or offset >= len(char_width):
            raise ValueError("offset must be between 0 and bytesPerChar")
        self.char_width = char_width
        self.bytes_per_char = len(char_width)
        self.offset = offset
        char_alignment = max(alignment // self.bytes_per_char, 1)
        self.char_matcher = MinLengthCharSequenceMatcher(min_length, char_set, char_alignment)
        converter = DataConverter(endian.is_big_endian())
        self.bytes = [0] * len(char_width)

    def compute_char_sequence_alignemt(self, alignment, bytes_in_char):
        return max(alignment // bytes_in_char, 1)

    def add(self, b):
        if self.char_width == 'UTF8':  # if only one byte per char, take shortcut
            return self.char_matcher.add_char(b & 0xff)
        
        self.index += 1
        if self.index < self.offset:
            return False
        
        mod = (self.index - self.offset) % self.bytes_per_char
        self.bytes[mod] = b

        if mod < self.bytes_per_char - 1:
            return False
        
        c = converter.get_short(self.bytes) if self.bytes_per_char == 2 else converter.get_int(self.bytes)
        return self.char_matcher.add_char(c)

    def get_sequence(self):
        sequence = self.char_matcher.get_sequence()
        if sequence is None or self.char_width == 'UTF8':
            return sequence
        
        start = sequence.start * self.bytes_per_char + self.offset
        end = (sequence.end + 1) * self.bytes_per_char - 1 + self.offset
        string_datatype = UnicodeDataType.data_type if self.char_width == 'UTF16' else Unicode32DataType.data_type
        return Sequence(start, end, string_datatype, sequence.is_null_terminated())

    def end_sequence(self):
        return self.char_matcher.end_sequence()

    def reset(self):
        self.index = -1
        self.char_matcher.reset()
