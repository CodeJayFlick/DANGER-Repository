Here is the translation of the Java code into Python:

```Python
class FunctionRepeatableCommentFieldLocation:
    def __init__(self, program, location_addr, function_addr=None, comment=None, row=0, char_offset=0):
        super().__init__(program, location_addr, function_addr, row, 0, char_offset)
        self.comment_array = comment

    @classmethod
    def from_function_addr(cls, program, function_addr, comment, row, col):
        return cls(program, function_addr, None, comment, row, col)

    def __init__(self):
        pass

    @property
    def comment(self):
        return self.comment_array


class FunctionLocation:
    def __init__(self, program, location_addr, function_addr=None, row=0, char_offset=0):
        self.program = program
        self.location_addr = location_addr
        self.function_addr = function_addr
        self.row = row
        self.char_offset = char_offset

    @property
    def hash(self):
        return hash((super().hash(), tuple(self.comment_array)))

    def __eq__(self, other):
        if not isinstance(other, FunctionRepeatableCommentFieldLocation):
            return False
        if super().__neq__(other):
            return False
        return self.comment_array == other.comment_array

    @property
    def save_state(self):
        state = SaveState()
        super().save_state(state)
        state.put_strings("_COMMENT", self.comment_array)
        return state


class Program:
    pass


def main():
    program = Program()
    location_addr = "location addr"
    function_addr = "function addr"
    comment = ["comment1", "comment2"]
    row = 0
    char_offset = 0

    frcfl = FunctionRepeatableCommentFieldLocation(program, location_addr, function_addr, comment, row, char_offset)
    print(frcfl.comment)

if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent of Java's `package`, so I removed it. Also, Python has no concept of static methods or constructors like in Java.