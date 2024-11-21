Here is the translation of the given Java code into Python:

```Python
class GDataConverterLE:
    INSTANCE = None

    def __init__(self):
        if not isinstance(self.INSTANCE, self.__class__):
            self.INSTANCE = self

    @staticmethod
    def get_short(b, offset=0):
        return (b[offset + 1] & 0xff) << 8 | b[offset] & 0xff

    @staticmethod
    def get_int(b, offset=0):
        v = b[offset + 3]
        for i in range(2, -1, -1):
            v = (v << 8) | (b[offset + i] & 0xff)
        return v

    @staticmethod
    def get_long(b, offset=0):
        v = b[offset + 7]
        for i in range(6, -1, -1):
            v = (v << 8) | (b[offset + i] & 0xff)
        return v

    @staticmethod
    def get_value(b, size, offset=0):
        if size > 8:
            raise IndexError("size exceeds sizeof long: " + str(size))
        val = 0
        for i in range(size - 1, -1, -1):
            val = (val << 8) | (b[offset + i] & 0xff)
        return val

    @staticmethod
    def get_bytes(value, b, offset=0):
        if isinstance(value, int):
            value = int.to_bytes(value, 4, 'little')
        elif isinstance(value, float):
            raise ValueError("Unsupported type for bytes conversion")
        else:
            raise TypeError("Invalid argument type")

        b[offset:offset + len(value)] = value

    @staticmethod
    def put_int(b, offset=0, value=int(0)):
        get_bytes(int.to_bytes(value, 4, 'little'), b, offset)

    @staticmethod
    def put_long(b, offset=0, value=int(0)):
        get_bytes(int.to_bytes(value, 8, 'little'), b, offset)

    @staticmethod
    def put_short(b, offset=0, value=int(0)):
        get_bytes(int.to_bytes(value, 2, 'little'), b, offset)
```

Please note that Python does not support static methods or variables like Java.