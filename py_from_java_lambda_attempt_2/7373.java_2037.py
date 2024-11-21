Here is the translation of the given Java code into Python:

```Python
class BoardTag:
    def __init__(self, reader):
        self.board = reader.read_int()

    @property
    def board(self):
        return self._board


import io


class BinaryReader(io.IOBase):
    def read_next_int(self):
        # implement your logic to read an integer from the binary file here
        pass

# usage example:
reader = BinaryReader()
tag = BoardTag(reader)
print(tag.board)  # prints the board value
```

Please note that this is a translation and not a direct copy. Python does not have built-in support for classes like Java, so we use the `class` keyword to define a class in Python. The constructor (`__init__`) is used instead of a constructor with parameters. Properties are implemented using getter methods (the `@property` decorator).