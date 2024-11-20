import hashlib
import struct

class GroupedLSBWatermarkEncoder:
    def __init__(self, secret_key: str, bit_string: str):
        self.secret_key = secret_key
        self.bit_string = bit_string
        self.group_number = len(bit_string)

    @staticmethod
    def hash_mod(val: str, base: int) -> int:
        md5_hash = hashlib.md5()
        try:
            md5_hash.update(val.encode())
        except Exception as e:
            raise RuntimeError("ERROR: Cannot find MD5 algorithm!") from e

        result_integer = int.from_bytes(md5_hash.digest(), 'big')
        return result_integer % base

    def need_encode(self, timestamp: long) -> bool:
        return self.hash_mod(f"{self.secret_key}{timestamp}", 2) == 0

    def get_group_id(self, timestamp: long) -> int:
        return self.hash_mod(f"{timestamp}{self.secret_key}", self.group_number)

    def get_bit_position(self, timestamp: long) -> int:
        if self.max_bit_position <= self.min_bit_position:
            raise RuntimeError("Error: minBitPosition is bigger than maxBitPosition")

        range_ = self.max_bit_position - self.min_bit_position
        return self.min_bit_position + self.hash_mod(f"{self.secret_key}{timestamp}{self.secret_key}", range_)

    def get_bit_value(self, timestamp: long) -> bool:
        group_id = self.get_group_id(timestamp)
        bit_index = group_id % len(self.bit_string)
        return self.bit_string[bit_index] == '1'

    def encode_int(self, value: int, timestamp: long) -> int:
        target_bit_position = self.get_bit_position(timestamp)
        target_bit_value = self.get_bit_value(timestamp)

        if target_bit_value:
            mask = 1 << (target_bit_position - self.min_bit_position + 31)
        else:
            mask = ~mask

        return value & (~mask | (value >> (32 - target_bit_position) << (32 - target_bit_position)))

    def encode_long(self, value: long, timestamp: long) -> int:
        return struct.unpack('I', self.encode_int(int(value), timestamp))[0]

    def encode_float(self, value: float, timestamp: long) -> float:
        bits = struct.pack('<f', value)
        return struct.unpack('<f', bytes([self.encode_int(int.from_bytes(bits, 'little'), timestamp)]))[0]

    def encode_double(self, value: double, timestamp: long) -> double:
        bits = struct.pack('<d', value)
        return struct.unpack('<d', bytes([self.encode_long(int.from_bytes(struct.pack('<Q', int(value)), 'little'), timestamp)]))[0]

    def encode_record(self, record):
        if not self.need_encode(record.timestamp):
            return record

        fields = list(record.fields)
        for field in fields:
            if field is None or field.data_type is None:
                continue
            data_type = field.data_type
            value = field.value
            if data_type == 'INT32':
                value = self.encode_int(int(value), record.timestamp)
            elif data_type == 'INT64':
                value = self.encode_long(long(value), record.timestamp)
            elif data_type == 'FLOAT':
                value = self.encode_float(float(value), record.timestamp)
            elif data_type == 'DOUBLE':
                value = self.encode_double(double(value), record.timestamp)

        return RowRecord(record.timestamp, fields)
