class TSDataType:
    BOOLEAN = (0,)
    INT32 = (1,)
    INT64 = (2,)
    FLOAT = (3,)
    DOUBLE = (4,)
    TEXT = (5,)
    VECTOR = (6,)

    def __init__(self, type):
        self.type = type

    @classmethod
    def deserialize(cls, type):
        return cls.get_ts_data_type(type)

    @classmethod
    def get_ts_data_type(cls, type):
        if type == 0:
            return TSDataType.BOOLEAN
        elif type == 1:
            return TSDataType.INT32
        elif type == 2:
            return TSDataType.INT64
        elif type == 3:
            return TSDataType.FLOAT
        elif type == 4:
            return TSDataType.DOUBLE
        elif type == 5:
            return TSDataType.TEXT
        elif type == 6:
            return TSDataType.VECTOR
        else:
            raise ValueError("Invalid input: {}".format(type))

    @classmethod
    def deserialize_from(cls, buffer):
        return cls.deserialize(buffer.get())

    @classmethod
    def get_serialized_size(cls):
        return 1

    def serialize_to(self, byte_buffer):
        byte_buffer.put(self.serialize())

    def serialize_to(self, output_stream):
        output_stream.write(self.serialize().to_bytes(1, 'big'))

    def get_data_type_size(self):
        if self == TSDataType.BOOLEAN:
            return 1
        elif self in [TSDataType.INT32, TSDataType.FLOAT]:
            return 4
        else:
            return 8

    def serialize(self):
        return self.type[0]
