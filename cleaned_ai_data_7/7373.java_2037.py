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
