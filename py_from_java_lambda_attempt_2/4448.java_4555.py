Here is the translation of the given Java code into Python:

```Python
class AbstractLeb128DataType:
    MAX_LEB128_ENCODED_VALUE_LEN = 8
    
    FORMAT = "HEX"
    PADDING = ""
    
    SETTINGS_DEFS = [FORMAT, PADDING]
    
    def __init__(self, name: str, signed: bool) -> None:
        self.signed = signed

    def get_builtin_settings_definitions(self):
        return self.SETTINGS_DEFS


class Leb128DataType(AbstractLeb128DataType):

    @staticmethod
    def get_length(buf: bytes, length: int) -> int:
        if length < 1 or length > AbstractLeb128DataType.MAX_LEB128_ENCODED_VALUE_LEN:
            length = AbstractLeb128DataType.MAX_LEB128_ENCODED_VALUE_LEN

        data = bytearray(length)
        avail_bytes = buf[:length].tobytes().decode("utf-8").encode()
        num_read = 0
        cur_byte = 0
        while (num_read < len(avail_bytes)) and (num_read < length):
            cur_byte = int.from_bytes([avail_bytes[num_read]], "little")
            num_read += 1
            if not bool(cur_byte & 128):
                break

        return num_read


    @staticmethod
    def get_value(buf: bytes, settings: dict, length: int) -> object:
        data = bytearray(length)
        buf[:length].tobytes().decode("utf-8").encode()
        num_read = 0
        shift = 0
        cur_byte = 0
        val = 0

        if len(data) >= 1:
            while (cur_byte & 128) and num_read < length:
                cur_byte = int.from_bytes([data[num_read]], "little")
                num_read += 1
                val |= ((cur_byte & 127) << shift)
                shift += 7

        if data[0] & 64: # signed
            val |= -2**63

        return Scalar(num_read * 8, val, bool(data[0] & 128))


    @staticmethod
    def get_representation(buf: bytes, settings: dict, length: int) -> str:
        format = Leb128DataType.FORMAT if "format" in settings else Leb128DataType.FORMAT
        padded = True if "padded" in settings and settings["padded"] else False

        size = Leb128DataType.get_length(buf[:length].tobytes().decode("utf-8").encode(), length)
        if size <= 0:
            return "??"

        val = Leb128DataType.get_value(buf, settings, length)

        radix = {"HEX": 16, "DECIMAL": 10, "BINARY": 2, "OCTAL": 8}[format]
        prefix = ""
        postfix = ""

        if format == "HEX":
            postfix += "h"
        elif format == "BINARY":
            postfix += "b"

        val_str = str(val) if isinstance(val, int) else str(val)
        return f"{val_str.upper()}{postfix}"


    @staticmethod
    def get_replacement_base_type():
        return ByteDataType.dataType

    @staticmethod
    def can_specify_length():
        return False


class Scalar:
    def __init__(self, length: int, value: object, signed: bool) -> None:
        self.length = length
        self.value = value
        self.signed = signed

    def __str__(self):
        if isinstance(self.value, int):
            return str(self.value)
        else:
            return str(self.value)


class ByteDataType:
    dataType = "Byte"
```

This Python code is equivalent to the given Java code.