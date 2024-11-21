class BinaryCodedField:
    BYTE_ARRAY = 0
    FLOAT = 1
    DOUBLE = 2
    SHORT_ARRAY = 3
    INT_ARRAY = 4
    LONG_ARRAY = 5
    FLOAT_ARRAY = 6
    DOUBLE_ARRAY = 7
    STRING_ARRAY = 8

    DATA_TYPE_OFFSET = 0
    DATA_OFFSET = 1

    STRING_ENCODING = "UTF-8"

    def __init__(self):
        pass

    @classmethod
    def from_binary_field(cls, bin_field):
        field = BinaryCodedField()
        field.data = bin_field.binary_data
        return field

    @classmethod
    def from_double_value(cls, value):
        buffer = bytearray(9)
        buffer[BinaryCodedField.DATA_TYPE_OFFSET] = cls.DOUBLE
        buffer[4:8] = Double.doubleToLongBits(value).to_bytes()
        data = bytes(buffer)
        return BinaryCodedField(data)

    @classmethod
    def from_float_value(cls, value):
        buffer = bytearray(5)
        buffer[BinaryCodedField.DATA_TYPE_OFFSET] = cls.FLOAT
        buffer[4:] = Float.floatToIntBits(value).to_bytes()
        data = bytes(buffer)
        return BinaryCodedField(data)

    @classmethod
    def from_byte_array(cls, values):
        if values is None:
            data = bytearray(2)
            data[0] = -1
        else:
            data = bytearray(len(values) + 2)
            data[BinaryCodedField.DATA_TYPE_OFFSET] = cls.BYTE_ARRAY
            System.arraycopy(values, 0, data, 2, len(values))
        return BinaryCodedField(data)

    @classmethod
    def from_short_array(cls, values):
        if values is None:
            buffer = bytearray(2)
            buffer[0] = -1
        else:
            buffer = bytearray(len(values) * 2 + 2)
            buffer[BinaryCodedField.DATA_TYPE_OFFSET] = cls.SHORT_ARRAY
            offset = BinaryCodedField.DATA_OFFSET
            for value in values:
                buffer[offset:offset+2] = int(value).to_bytes()
                offset += 2
        data = bytes(buffer)
        return BinaryCodedField(data)

    @classmethod
    def from_int_array(cls, values):
        if values is None:
            buffer = bytearray(2)
            buffer[0] = -1
        else:
            buffer = bytearray(len(values) * 4 + 2)
            buffer[BinaryCodedField.DATA_TYPE_OFFSET] = cls.INT_ARRAY
            offset = BinaryCodedField.DATA_OFFSET
            for value in values:
                buffer[offset:offset+4] = int(value).to_bytes()
                offset += 4
        data = bytes(buffer)
        return BinaryCodedField(data)

    @classmethod
    def from_long_array(cls, values):
        if values is None:
            buffer = bytearray(2)
            buffer[0] = -1
        else:
            buffer = bytearray(len(values) * 8 + 2)
            buffer[BinaryCodedField.DATA_TYPE_OFFSET] = cls.LONG_ARRAY
            offset = BinaryCodedField.DATA_OFFSET
            for value in values:
                buffer[offset:offset+8] = int(value).to_bytes()
                offset += 8
        data = bytes(buffer)
        return BinaryCodedField(data)

    @classmethod
    def from_float_array(cls, values):
        if values is None:
            buffer = bytearray(2)
            buffer[0] = -1
        else:
            buffer = bytearray(len(values) * 4 + 2)
            buffer[BinaryCodedField.DATA_TYPE_OFFSET] = cls.FLOAT_ARRAY
            offset = BinaryCodedField.DATA_OFFSET
            for value in values:
                buffer[offset:offset+4] = Float.floatToIntBits(value).to_bytes()
                offset += 4
        data = bytes(buffer)
        return BinaryCodedField(data)

    @classmethod
    def from_double_array(cls, values):
        if values is None:
            buffer = bytearray(2)
            buffer[0] = -1
        else:
            buffer = bytearray(len(values) * 8 + 2)
            buffer[BinaryCodedField.DATA_TYPE_OFFSET] = cls.DOUBLE_ARRAY
            offset = BinaryCodedField.DATA_OFFSET
            for value in values:
                buffer[offset:offset+8] = Double.doubleToLongBits(value).to_bytes()
                offset += 8
        data = bytes(buffer)
        return BinaryCodedField(data)

    @classmethod
    def from_string_array(cls, strings):
        if strings is None:
            buffer = bytearray(2)
            buffer[0] = -1
        else:
            buffer = bytearray(len(strings) * (4 + len(str(len(strings))) + sum(len(s.encode()) for s in strings)) + 2)
            buffer[BinaryCodedField.DATA_TYPE_OFFSET] = cls.STRING_ARRAY
            offset = BinaryCodedField.DATA_OFFSET
            for string in strings:
                if string is None:
                    buffer[offset:offset+4] = -1.to_bytes()
                else:
                    len_str = len(string.encode()).to_bytes()
                    buffer[offset:offset+4] = len_str + string.encode('UTF-8')
                offset += 4
        data = bytes(buffer)
        return BinaryCodedField(data)

    def get_data_type(self):
        return self.data[BinaryCodedField.DATA_TYPE_OFFSET]

    def get_double_value(self):
        if self.get_data_type() != self.DOUBLE:
            raise IllegalFieldAccessException()
        buffer = BytesIO(self.data)
        value = Double.longBitsToDouble(buffer.read_long())
        return value

    def get_float_value(self):
        if self.get_data_type() != self.FLOAT:
            raise IllegalFieldAccessException()
        buffer = BytesIO(self.data)
        value = Float.intBitsToFloat(buffer.read_int())
        return value

    def get_byte_array(self):
        if self.get_data_type() != self.BYTE_ARRAY:
            raise IllegalFieldAccessException()
        if self.data[BinaryCodedField.DATA_OFFSET] < 0:
            return None
        values = bytearray(len(self.data) - 2)
        System.arraycopy(self.data, 2, values, 0, len(values))
        return bytes(values)

    def get_short_array(self):
        if self.get_data_type() != self.SHORT_ARRAY:
            raise IllegalFieldAccessException()
        if self.data[BinaryCodedField.DATA_OFFSET] < 0:
            return None
        buffer = BytesIO(self.data)
        values = []
        offset = BinaryCodedField.DATA_OFFSET + 1
        while True:
            value = int.from_bytes(buffer.read(2), 'big')
            values.append(value)
            if buffer.tell() == len(self.data):
                break
        return bytes(values)

    def get_int_array(self):
        if self.get_data_type() != self.INT_ARRAY:
            raise IllegalFieldAccessException()
        if self.data[BinaryCodedField.DATA_OFFSET] < 0:
            return None
        buffer = BytesIO(self.data)
        values = []
        offset = BinaryCodedField.DATA_OFFSET + 1
        while True:
            value = int.from_bytes(buffer.read(4), 'big')
            values.append(value)
            if buffer.tell() == len(self.data):
                break
        return bytes(values)

    def get_long_array(self):
        if self.get_data_type() != self.LONG_ARRAY:
            raise IllegalFieldAccessException()
        if self.data[BinaryCodedField.DATA_OFFSET] < 0:
            return None
        buffer = BytesIO(self.data)
        values = []
        offset = BinaryCodedField.DATA_OFFSET + 1
        while True:
            value = int.from_bytes(buffer.read(8), 'big')
            values.append(value)
            if buffer.tell() == len(self.data):
                break
        return bytes(values)

    def get_float_array(self):
        if self.get_data_type() != self.FLOAT_ARRAY:
            raise IllegalFieldAccessException()
        if self.data[BinaryCodedField.DATA_OFFSET] < 0:
            return None
        buffer = BytesIO(self.data)
        values = []
        offset = BinaryCodedField.DATA_OFFSET + 1
        while True:
            value = Float.intBitsToFloat(int.from_bytes(buffer.read(4), 'big'))
            values.append(value)
            if buffer.tell() == len(self.data):
                break
        return bytes(values)

    def get_double_array(self):
        if self.get_data_type() != self.DOUBLE_ARRAY:
            raise IllegalFieldAccessException()
        if self.data[BinaryCodedField.DATA_OFFSET] < 0:
            return None
        buffer = BytesIO(self.data)
        values = []
        offset = BinaryCodedField.DATA_OFFSET + 1
        while True:
            value = Double.longBitsToDouble(int.from_bytes(buffer.read(8), 'big'))
            values.append(value)
            if buffer.tell() == len(self.data):
                break
        return bytes(values)

    def get_string_array(self):
        if self.get_data_type() != self.STRING_ARRAY:
            raise IllegalFieldAccessException()
        if self.data[BinaryCodedField.DATA_OFFSET] < 0:
            return None
        buffer = BytesIO(self.data)
        values = []
        offset = BinaryCodedField.DATA_OFFSET + 1
        while True:
            length = int.from_bytes(buffer.read(4), 'big')
            value = buffer.read(length).decode('UTF-8')
            if value is not None and len(value) > 0:
                values.append(value)
            else:
                values.append(None)
            if buffer.tell() == len(self.data):
                break
        return bytes(values)

class IllegalFieldAccessException(Exception):
    pass

class BytesIO(io.BytesIO):
    def read_long(self):
        value = int.from_bytes(self.read(8), 'big')
        return value

    def read_int(self):
        value = int.from_bytes(self.read(4), 'big')
        return value
