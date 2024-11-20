Here is the translation of the Java code into Python:

```Python
class PdbByteWriter:
    padding_bytes = bytes([0xf4, 0xf3, 0xf2, 0xf1])
    align_bytes = bytes([0x00] * 4)

    def __init__(self):
        self.output_stream = bytearray()
        self.reset()

    def reset(self):
        self.output_stream.clear()

    @property
    def size(self):
        return len(self.output_stream)

    def get(self):
        return bytes(self.output_stream)

    def put_bytes(self, bytes_):
        self.output_stream.extend(bytes_)

    def put_padding(self, disallow):
        mod = 4 * ((len(self.output_stream) - disallow + 3) // 4) - (len(self.output_stream) - disallow)
        if mod > 0:
            self.put_bytes(self.padding_bytes[:mod])

    def put_align(self, disallow):
        mod = 4 * ((len(self.output_stream) - disallow + 3) // 4) - (len(self.output_stream) - disallow)
        if mod > 0:
            self.put_bytes(self.align_bytes[:mod])

    def put_unsigned_byte(self, value):
        byte_array = bytearray(1)
        byte_array[0] = value & 0xff
        self.put_bytes(byte_array)

    def put_short(self, value):
        little_endian_data_converter = LittleEndianDataConverter()
        scratch_array = bytearray(2)
        little_endian_data_converter.put_short(scratch_array, value)
        self.put_bytes(scratch_array)

    def put_unsigned_short(self, value):
        little_endian_data_converter = LittleEndianDataConverter()
        scratch_array = bytearray(2)
        little_endian_data_converter.put_short(scratch_array, (value & 0xffff))
        self.put_bytes(scratch_array)

    def put_int(self, value):
        little_endian_data_converter = LittleEndianDataConverter()
        scratch_array = bytearray(4)
        little_endian_data_converter.put_int(scratch_array, value)
        self.put_bytes(scratch_array)

    def put_unsigned_int(self, value):
        little_endian_data_converter = LittleEndianDataConverter()
        scratch_array = bytearray(4)
        little_endian_data_converter.put_int(scratch_array, (value & 0xffffffff))
        self.put_bytes(scratch_array)

    def put_long(self, value):
        little_endian_data_converter = LittleEndianDataConverter()
        scratch_array = bytearray(8)
        little_endian_data_converter.put_long(scratch_array, value)
        self.put_bytes(scratch_array)

    def put_unsigned_long(self, value):
        little_endian_data_converter = LittleEndianDataConverter()
        scratch_array = bytearray(8)
        little_endian_data_converter.put_long(scratch_array, (value & 0xffffffffffffffff))
        self.put_bytes(scratch_array)

    def put_numeric(self, value, code):
        if isinstance(value, int):
            value = BigInteger(str(value), 16).and_(BigInteger("ffffffffffffff", 16)).longValue()
        elif not isinstance(value, BigInteger):
            raise ValueError('Invalid type for numeric value')
        
        switcher = {
            0x8000: self.put_char,
            0x8001: self.put_short,
            0x8002: self.put_unsigned_short,
            0x8003: self.put_int,
            0x8004: self.put_unsigned_int,
            0x8009: self.put_long,
            0x800a: self.put_unsigned_long
        }
        
        switcher.get(code, lambda x: None)(value)

    def put_char(self, value):
        byte_array = bytearray(2)
        little_endian_data_converter = LittleEndianDataConverter()
        little_endian_data_converter.put_short(byte_array, (value & 0xffff))
        self.put_bytes(byte_array)

    def put_GUID(self, data1, data2, data3, data4):
        if len(data4) != 8:
            raise ValueError('Invalid GUID byte array size')
        
        self.put_int(data1)
        self.put_short(data2)
        self.put_short(data3)
        self.put_bytes(data4)

    def put_byte_length_prefixed_string(self, string):
        length = len(string.encode())
        if length > 255:
            raise ValueError('length > 255')

        byte_array = bytearray(1)
        byte_array[0] = length
        self.put_bytes(byte_array)
        
        self.put_bytes(string.encode())

    def put_byte_length_prefixed_utf8_string(self, string):
        length = len(string.encode('utf-8'))
        if length > 255:
            raise ValueError('length > 255')

        byte_array = bytearray(1)
        byte_array[0] = length
        self.put_bytes(byte_array)

        self.put_bytes(string.encode('utf-8'))

    def put_null_terminated_string(self, string):
        byte_array = string.encode()
        for char in byte_array:
            if char == 0:
                break
            self.put_bytes(char.to_bytes(1, 'big'))
        
        self.put_bytes(b'\x00')

    def put_null_terminated_utf8_string(self, string):
        byte_array = string.encode('utf-8')
        for char in byte_array:
            if char == 0:
                break
            self.put_bytes(char.to_bytes(1, 'big'))

        self.put_bytes(b'\x00')

    def put_null_terminated_wchart_string(self, string):
        byte_array = string.encode('utf-16le')
        for char in byte_array:
            if char == 0:
                break
            self.put_bytes(char.to_bytes(2, 'little'))
        
        self.put_bytes(b'\x00\x00')

class LittleEndianDataConverter:

    @staticmethod
    def put_short(byte_array, value):
        byte_array[1] = (value & 0xff)
        byte_array[0] = ((value >> 8) & 0xff)

    @staticmethod
    def put_int(byte_array, value):
        byte_array[3] = (value & 0xff)
        byte_array[2] = ((value >> 8) & 0xff)
        byte_array[1] = ((value >> 16) & 0xff)
        byte_array[0] = ((value >> 24) & 0xff)

    @staticmethod
    def put_long(byte_array, value):
        byte_array[7] = (value & 0ff)
        byte_array[6] = ((value >> 8) & 0ff)
        byte_array[5] = ((value >> 16) & 0ff)
        byte_array[4] = ((value >> 24) & 0ff)
        byte_array[3] = ((value >> 32) & 0ff)
        byte_array[2] = ((value >> 40) & 0ff)
        byte_array[1] = ((value >> 48) & 0ff)
        byte_array[0] = ((value >> 56) & 0ff)

    @staticmethod
    def put_unsigned_long(byte_array, value):
        byte_array[7] = (value & 0xff)
        byte_array[6] = ((value >> 8) & 0xff)
        byte_array[5] = ((value >> 16) & 0xff)
        byte_array[4] = ((value >> 24) & 0xff)
        byte_array[3] = ((value >> 32) & 0xff)
        byte_array[2] = ((value >> 40) & 0xff)
        byte_array[1] = ((value >> 48) & 0xff)
        byte_array[0] = ((value >> 56) & 0ff)

    @staticmethod
    def put_unsigned_int(byte_array, value):
        byte_array[3] = (value & 0xff)
        byte_array[2] = ((value >> 8) & 0xff)
        byte_array[1] = ((value >> 16) & 0xff)
        byte_array[0] = ((value >> 24) & 0ff)

    @staticmethod
    def put_unsigned_short(byte_array, value):
        byte_array[1] = (value & 0xff)
        byte_array[0] = ((value >> 8) & 0ff)

    @staticmethod
    def put_char(byte_array, value):
        byte_array[1] = (value & 0xff)
        byte_array[0] = ((value >> 8) & 0ff)

```

This Python code is a direct translation of the provided Java code. It includes classes `PdbByteWriter` and `LittleEndianDataConverter`. The `PdbByteWriter` class provides methods for writing various types of data to an output stream, while the `LittleEndianDataConverter` class contains static methods for converting integers into little-endian byte arrays.