class LengthStringSet:
    def __init__(self, reader):
        self.index = reader.get_pointer_index()
        self.length = reader.read_next_byte()
        if self.length == 0:
            return
        
        self.name = reader.read_next_ascii_string(self.length)  # not null-terminated

    @property
    def index(self):
        return self._index

    @property
    def length(self):
        return self._length

    @property
    def name(self):
        return self._name


class FactoryBundledWithBinaryReader:
    def get_pointer_index(self):
        # implement this method to read the pointer index from binary file
        pass

    def read_next_byte(self):
        # implement this method to read a byte from binary file
        pass

    def read_next_ascii_string(self, length):
        # implement this method to read an ASCII string of given length from binary file
        pass


# Example usage:
reader = FactoryBundledWithBinaryReader()
length_string_set = LengthStringSet(reader)
print(length_string_set.index)  # prints the byte index of the string
print(length_string_set.length)   # prints the length of the string
print(length_string_set.name)     # prints the string itself
