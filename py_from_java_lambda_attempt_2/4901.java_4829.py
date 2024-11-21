Here is the translation of the given Java code into Python:

```Python
class ResourceStringTable:
    def __init__(self):
        self.strings = []

    def construct(self, reader, rt) -> None:
        super().__init__()
        bytes_array = reader.get_bytes()
        for i in range(len(bytes_array)):
            if bytes_array[i] != 0:
                old_index = reader.get_pointer_index()
                reader.set_pointer_index(reader.get_file_offset_shifted() + i)
                lss = LengthStringSet(reader)
                if lss.get_length() == 0:
                    break
                self.strings.append(lss)
                i += (lss.get_length().value + 1)
                reader.set_pointer_index(old_index)

    def get_strings(self) -> list:
        return self.strings


class LengthStringSet:
    def __init__(self, reader):
        pass

    def get_length(self) -> int:
        pass
```

Please note that the `LengthStringSet` class and its methods (`get_length`) are not implemented in this translation as they were missing from your original Java code.