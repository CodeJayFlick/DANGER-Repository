class VectorIterator:
    def __init__(self, data, index):
        self.data = data
        self.index = index

    def __str__(self):
        if self.index >= len(self.data):
            value = None
        else:
            value = self.data[self.index]
        return f"VectorIterator: [index={self.index} - {value}]"

    def assign(self, other_iterator):
        other = VectorIterator(other_iterator.data, other_iterator.index)
        self.index = other.index
        self.data = other.data

    @property
    def is_begin(self):
        return self.index == 0

    @property
    def is_end(self):
        return self.index >= len(self.data)

    def get(self):
        if self.is_end:
            raise IndexError("Index out of bounds")
        return self.data[self.index]

    def set(self, value):
        if not self.is_begin and not self.is_end:
            self.data[self.index] = value
        else:
            raise IndexError("Index out of bounds")

    def get_at_offset(self, offset):
        if self.is_end or (self.is_begin and offset > 0):
            raise IndexError("Index out of bounds")
        return self.data[self.index + offset]

    def decrement(self):
        if self.is_begin:
            raise IndexError("Index out of bounds")
        self.index -= 1
        return self

    def increment(self, count=1):
        if not (self.is_end and count == 0) or (not self.is_begin and count > 0):
            for _ in range(count):
                if self.is_end:
                    raise IndexError("Index out of bounds")
                self.index += 1
        return self

    def decrement_at_offset(self, offset=0):
        if not (self.is_end and -offset >= len(self.data)) or (not self.is_begin and offset > 0):
            for _ in range(offset):
                if self.is_end:
                    raise IndexError("Index out of bounds")
                self.index -= 1
        return self

    def insert(self, value):
        if not self.is_end:
            self.data.insert(self.index, value)
        else:
            self.data.append(value)

    def __eq__(self, other):
        if isinstance(other, VectorIterator):
            return self.data == other.data and self.index == other.index
        return False

    def __hash__(self):
        return hash(tuple(self.data))

    def copy(self):
        return VectorIterator(self.data[:], self.index)

    @property
    def index_(self):
        return self.index
