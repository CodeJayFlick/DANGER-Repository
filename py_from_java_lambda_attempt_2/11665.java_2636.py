Here is the equivalent Python code:

```Python
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
```

Note that Python does not have direct equivalents to Java's `public` and `private` access modifiers. In Python, all attributes are public by default, but you can use the underscore prefix (`_`) to indicate that an attribute is intended to be private (i.e., it should not be accessed directly from outside the class).