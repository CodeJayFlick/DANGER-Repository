Here is the equivalent Python code:

```Python
class Ext4XattrHeader:
    def __init__(self, provider):
        self.h_magic = 0
        self.h_refcount = 0
        self.h_blocks = 0
        self.h_hash = 0
        self.h_checksum = 0
        self.h_reserved = [0, 0]

    @classmethod
    def from_provider(cls, provider):
        reader = BinaryReader(provider)
        cls(reader)

    @classmethod
    def from_reader(cls, reader):
        cls.h_magic = reader.read_int()
        cls.h_refcount = reader.read_int()
        cls.h_blocks = reader.read_int()
        cls.h_hash = reader.read_int()
        cls.h_checksum = reader.read_int()
        cls.h_reserved = [reader.read_int(), reader.read_int()]

    def get_h_magic(self):
        return self.h_magic

    def get_h_refcount(self):
        return self.h_refcount

    def get_h_blocks(self):
        return self.h_blocks

    def get_h_hash(self):
        return self.h_hash

    def get_h_checksum(self):
        return self.h_checksum

    def get_h_reserved(self):
        return self.h_reserved


class BinaryReader:
    def __init__(self, provider):
        pass  # Implement the actual binary reader logic here

    def read_int(self):
        raise NotImplementedError("Method not implemented")

    def read_array(self, size):
        result = []
        for _ in range(size):
            result.append(self.read_int())
        return result


class DataType:
    pass


def main():
    provider = None  # Replace with your actual binary data
    header = Ext4XattrHeader(provider)
    print(header.get_h_magic())


if __name__ == "__main__":
    main()
```

Please note that the `BinaryReader` class is not fully implemented in this code. You would need to implement it based on how you are reading your binary data, which was not provided in the original Java code.