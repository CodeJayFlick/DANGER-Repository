Here is the translation of the given Java code into Python:

```Python
class FloatEncoder:
    def __init__(self, encoding_type: str, data_type: str, max_point_number: int):
        self.max_point_number = max_point_number
        if encoding_type == "RLE":
            if data_type == "FLOAT":
                self.encoder = IntRleEncoder()
            elif data_type == "DOUBLE":
                self.encoder = LongRleEncoder()
            else:
                raise TsFileEncodingException(f"Data type {data_type} is not supported by FloatEncoder")
        elif encoding_type == "TS_2DIFF":
            if data_type == "FLOAT":
                self.encoder = DeltaBinaryEncoder.IntDeltaEncoder()
            elif data_type == "DOUBLE":
                self.encoder = DeltaBinaryEncoder.LongDeltaEncoder()
            else:
                raise TsFileEncodingException(f"Data type {data_type} is not supported by FloatEncoder")
        else:
            raise TsFileEncodingException(f"{encoding_type} encoding is not supported by FloatEncoder")

    def encode(self, value: float, out):
        self.save_max_point_number(out)
        value_int = int(round(value * (10 ** self.max_point_number)))
        self.encoder.encode(value_int, out)

    def encode_double(self, value: double, out):
        self.save_max_point_number(out)
        value_long = round(value * (10 ** self.max_point_number))
        self.encoder.encode(value_long, out)

    def calculate_max_ponit_num(self):
        if self.max_point_number <= 0:
            self.max_point_number = 0
            self.max_point_value = 1.0
        else:
            self.max_point_value = pow(10, self.max_point_number)

    def convert_float_to_int(self, value: float) -> int:
        return round(value * self.max_point_value)

    def convert_double_to_long(self, value: double) -> long:
        return round(value * self.max_point_value)

    def flush(self, out):
        self.encoder.flush(out)
        self.reset()

    def reset(self):
        self.is_max_point_number_saved = False

    def save_max_point_number(self, out):
        if not self.is_max_point_number_saved:
            ReadWriteForEncodingUtils.write_unsigned_var_int(self.max_point_number, out)
            self.is_max_point_number_saved = True

    @property
    def one_item_max_size(self) -> int:
        return self.encoder.one_item_max_size()

    @property
    def max_byte_size(self) -> long:
        return self.encoder.max_byte_size()
```

Note: The above Python code assumes that the following classes are defined:

- `IntRleEncoder`
- `LongRleEncoder`
- `DeltaBinaryEncoder.IntDeltaEncoder()`
- `DeltaBinaryEncoder.LongDeltaEncoder()`
- `TsFileEncodingException`