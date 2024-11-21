Here is the equivalent Python code:

```Python
class ImageFunctionEntry:
    def __init__(self):
        self.starting_address = 0
        self.ending_address = 0
        self.end_of_prologue_address = 0

    @property
    def starting_address(self):
        return self._starting_address

    @starting_address.setter
    def starting_address(self, value):
        self._starting_address = value

    @property
    def ending_address(self):
        return self._ending_address

    @ending_address.setter
    def ending_address(self, value):
        self._ending_address = value

    @property
    def end_of_prologue_address(self):
        return self._end_of_prologue_address

    @end_of_prologue_address.setter
    def end_of_prologue_address(self, value):
        self._end_of_prologue_address = value

    def deserialize(self, reader):
        try:
            self.starting_address = int.from_bytes(reader.read(4), 'little')
            self.ending_address = int.from_bytes(reader.read(4), 'little')
            self.end_of_prologue_address = int.from_bytes(reader.read(4), 'little')
        except Exception as e:
            raise ValueError("Error deserializing ImageFunctionEntry: {}".format(str(e)))

    def __str__(self):
        return self.dump()

    def dump(self):
        output = "ImageFunctionEntry------------------------------------------\n"
        output += f"startingAddress: 0x{self.starting_address:x}\n"
        output += f"endingAddress: 0x{self.ending_address:x}\n"
        output += f"endOfPrologueAddress: 0x{self.end_of_prologue_address:x}\n"
        output += "End ImageFunctionEntry--------------------------------------\n"
        return output
```

This Python code defines a class `ImageFunctionEntry` with properties for starting address, ending address and end of prologue address. It also includes methods to deserialize the object from bytes read from a file or stream, and to dump its contents as a string.