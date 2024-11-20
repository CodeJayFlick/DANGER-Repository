Here is the translation of the given Java code into Python:

```Python
class CliStreamStrings:
    def __init__(self):
        self.string_indexes = []
        self.string_sizes = []

    @staticmethod
    def get_name():
        return "#Strings"

    def parse(self, header, offset, rva, reader) -> bool:
        super().__init__()
        string_length = 0
        prev_offset = 0

        while True:  # Loop through the data looking for NULL terminators
            current_byte = reader.read_next_unsigned_byte()
            string_length += 1

            if current_byte == 0:
                self.string_indexes.append(prev_offset)
                prev_offset = string_length + 1

                # Record the length of the UTF-8 string including the NULL terminator
                self.string_sizes.append(string_length)

                # We're moving on to the next string so reset to 0
                string_length = 0
            else:
                pass

        return True

    def get_string(self, index):
        if not self.string_indexes or not self.string_sizes:
            return None

        last_index = self.string_indexes[-1]
        last_size = self.string_sizes[-1]

        if index < 0 or index >= last_index + last_size:
            return None

        string_length = 0
        for i, idx in enumerate(self.string_indexes):
            if index == idx:
                break
            string_length += self.string_sizes[i]
        else:  # If the loop didn't terminate due to a break statement
            string_length -= (index - self.string_indexes[-1])

        try:
            return reader.read_byte_array(offset + index, string_length - 1).decode('utf-8')
        except Exception as e:
            return None

    def to_data_type(self) -> object:
        struct = StructureDataType(CategoryPath(PATH), header.name, 0)

        for i in range(len(self.string_sizes)):
            struct.add(UTF8, self.string_sizes[i], f"[{int.to_bytes(string_indexes[i]).hex()}]", None)
        return struct
```

Please note that this Python code is a direct translation of the given Java code. It may not be perfect and might require some adjustments to work correctly in your specific use case.