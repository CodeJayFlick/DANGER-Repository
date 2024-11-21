Here is the translation of the Java code into Python:

```Python
class CharacterIterator:
    DONE = '\uFFFF'

    def __init__(self, string):
        self.string = string
        self.index = 0

    @property
    def string(self):
        return self._string

    @string.setter
    def string(self, value):
        self._string = value

    @property
    def index(self):
        return self._index

    @index.setter
    def set_index(self, value):
        if 0 <= value < len(self.string):
            self._index = value
        else:
            raise ValueError("Index out of range")

    def get_length(self):
        return len(self.string)

    def has_next(self):
        return self.index < len(self.string)

    def peek(self):
        try:
            return self.string[self.index]
        except IndexError:
            return self.DONE

    def peek_at(self, look_ahead):
        try:
            return self.string[self.index + look_ahead]
        except IndexError:
            return self.DONE

    def next(self):
        try:
            result = self.string[self.index]
            self.set_index(self.index + 1)
            return result
        except IndexError:
            self.set_index(len(self.string) - 1)
            return self.DONE

    def get_and_increment(self):
        try:
            result = self.string[self.index]
            self.set_index(self.index + 1)
            return result
        except IndexError:
            self.set_index(len(self.string) - 1)
            return self.DONE

    def previous(self):
        try:
            result = self.string[self.index - 1]
            self.set_index(self.index - 1)
            return result
        except (IndexError, ValueError):
            self.set_index(0)
            return self.DONE

    def next_string(self, length):
        if self.index + length > len(self.string):
            raise ValueError("String out of range")
        s = self.string[self.index:self.index+length]
        self.set_index(self.index + length)
        return s

    def next_integer(self):
        orig_index = self.index
        while True:
            try:
                if not chr(peek()).isdigit():
                    break
                get_and_increment()
            except IndexError:
                index = len(self.string) - 1
                raise ValueError("Integer out of range")
        if orig_index == self.index:
            return ord(self.peek()) - ord('0')
        s = self.string[orig_index:self.index]
        try:
            return int(s)
        except ValueError as e:
            self.set_index(orig_index)
            raise e

    def find(self, c):
        for i in range(self.index, len(self.string)):
            if self.string[i] == c:
                return i
        return -1

    def __str__(self):
        return f"current = {chr(peek())}; next = {chr(peek_at(1))}"
```

Note that the `setIndex` method is now a property in Python, and it raises an exception if the index goes out of range. The `getAndIncrement`, `previous`, and `nextString` methods also raise exceptions if they go out of range.