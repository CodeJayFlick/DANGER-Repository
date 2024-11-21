Here is the translation of the given Java code into equivalent Python:

```Python
class Encoder:
    MAX_STRING_LENGTH = "max_string_length"
    MAX_POINT_NUMBER = "max_point_number"

    def __init__(self):
        pass

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    def encode_bool_value(self, boolean_value: bool) -> bytes:
        raise TsFileEncodingException("Method encode boolean is not supported by Encoder")

    def encode_short_value(self, short_value: int) -> bytes:
        raise TsFileEncodingException("Method encode short is not supported by Encoder")

    def encode_int_value(self, int_value: int) -> bytes:
        raise TsFileEncodingException("Method encode int is not supported by Encoder")

    def encode_long_value(self, long_value: int) -> bytes:
        raise TsFileEncodingException("Method encode long is not supported by Encoder")

    def encode_float_value(self, float_value: float) -> bytes:
        raise TsFileEncodingException("Method encode float is not supported by Encoder")

    def encode_double_value(self, double_value: float) -> bytes:
        raise TsFileEncodingException("Method encode double is not supported by Encoder")

    def encode_binary_value(self, binary_value: bytes) -> bytes:
        raise TsFileEncodingException("Method encode Binary is not supported by Encoder")

    def encode_big_decimal_value(self, big_decimal_value: 'decimal.Decimal') -> bytes:
        raise TsFileEncodingException("Method encode BigDecimal is not supported by Encoder")

    def flush(self):
        pass

class TsFileEncodingException(Exception):
    pass
```

Please note that Python does not have a direct equivalent to Java's `abstract` keyword. Instead, you can define an abstract method in the base class and then override it in any child classes as needed.

Also, there is no exact equivalent of Java's `ByteArrayOutputStream`. In Python, you would typically use the built-in `bytes` type or the `io.BytesIO` class to achieve similar functionality.