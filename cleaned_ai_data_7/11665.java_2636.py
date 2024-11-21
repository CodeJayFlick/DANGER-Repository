class Token:
    def __init__(self, name, size, bigendian, index):
        self.name = name
        self.size = size
        self.bigendian = bigendian
        self.index = index

    @property
    def get_size(self):
        return self.size

    @property
    def is_big_endian(self):
        return self.bigendian

    @property
    def get_index(self):
        return self.index

    @property
    def get_name(self):
        return self.name

    def __str__(self):
        if self.bigendian:
            endianness = "big"
        else:
            endianness = "little"

        return f"Token{{{self.name}:{self.size}:{self.index}:{endianness}}}"
