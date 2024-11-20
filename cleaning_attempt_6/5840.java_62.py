class CharWidth:
    UTF8 = (1,)
    UTF16 = (2,)
    UTF32 = (4,)

    def __init__(self, size):
        self.size = size

    @property
    def size(self):
        return self._size

CharWidth.UTF8 = CharWidth(1)
CharWidth.UTF16 = CharWidth(2)
CharWidth.UTF32 = CharWidth(4)
