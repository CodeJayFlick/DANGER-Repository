import logging

class PlainEncoder:
    def __init__(self, data_type: int, max_string_length: int):
        self.data_type = data_type
        self.max_string_length = max_string_length

    def encode(self, value: bool, out: bytearray) -> None:
        if value:
            out.append(1)
        else:
            out.append(0)

    def encode_short(self, value: int, out: bytearray) -> None:
        out.extend((value >> 8).to_bytes(1, 'big'))
        out.extend(value.to_bytes(1, 'big'))

    def encode_int(self, value: int, out: bytearray) -> None:
        ReadWriteForEncodingUtils.write_varint(value, out)

    def encode_long(self, value: int, out: bytearray) -> None:
        for i in range(7, -1, -1):
            out.extend(((value >> (i * 8)) & 0xFF).to_bytes(1, 'big'))

    def encode_float(self, value: float, out: bytearray) -> None:
        int_value = int(float(value))
        out.extend((int_value >> 24).to_bytes(1, 'big'))
        out.extend((int_value >> 16).to_bytes(1, 'big'))
        out.extend((int_value >> 8).to_bytes(1, 'big'))
        out.extend(int_value.to_bytes(1, 'big'))

    def encode_double(self, value: float, out: bytearray) -> None:
        self.encode_long(int(double(value)), out)

    def encode_binary(self, value: bytes, out: bytearray) -> None:
        try:
            # write the length of the bytes
            self.encode(len(value), out)
            # write value
            out.extend(value)
        except Exception as e:
            logging.error(f"tsfile-encoding PlainEncoder: error occurs when encode Binary value {value}: {e}")

    def flush(self, out: bytearray) -> None:
        pass

    def get_one_item_max_size(self) -> int:
        if self.data_type == 0:
            return 1
        elif self.data_type in [2, 3]:
            return 4
        elif self.data_type in [5, 6]:
            return 8
        elif self.data_type == 7:
            # refer to encode(Binaty, bytearray)
            return 4 + TSFileConfig.BYTE_SIZE_PER_CHAR * self.max_string_length
        else:
            raise ValueError(f"Unsupported data type: {self.data_type}")

    def get_max_byte_size(self) -> int:
        return 0

    def encode_big_decimal(self, value: float, out: bytearray) -> None:
        raise TsFileEncodingException("tsfile-encoding PlainEncoder: current version does not support BigDecimal value encoding")
