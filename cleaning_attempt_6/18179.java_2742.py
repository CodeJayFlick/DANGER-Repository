class ChunkHeader:
    def __init__(self,
                 chunk_type: bytes,
                 measurement_id: str,
                 data_size: int,
                 data_type: 'TSDataType',
                 compression_type: 'CompressionType',
                 encoding_type: 'TSEncoding'):
        self.chunk_type = chunk_type
        self.measurement_id = measurement_id
        self.data_size = data_size
        self.data_type = data_type
        self.compression_type = compression_type
        self.encoding_type = encoding_type

    @staticmethod
    def get_serialized_size(measurement_id: str, data_size: int) -> int:
        measurement_id_length = len(measurement_id.encode('utf-8'))
        return 1 + ReadWriteForEncodingUtils.var_int_size(measurement_id_length) \
               + measurement_id_length \
               + ReadWriteForEncodingUtils.u_var_int_size(data_size) \
               + TSDataType.get_serialized_size() \
               + CompressionType.get_serialized_size() \
               + TSEncoding.get_serialized_size()

    @staticmethod
    def deserialize_from(input_stream: bytes, chunk_type: int) -> 'ChunkHeader':
        measurement_id = ReadWriteIOUtils.read_var_int_string(input_stream)
        data_size = ReadWriteForEncodingUtils.read_unsigned_var_int(input_stream)
        data_type = TSDataType.deserialize(input_stream)
        compression_type = CompressionType.deserialize(input_stream)
        encoding_type = TSEncoding.deserialize(input_stream)
        return ChunkHeader(chunk_type, measurement_id, data_size, data_type, compression_type, encoding_type)

    @staticmethod
    def deserialize_from_tsfile_input(ts_file_input: 'TsFileInput', offset: int, chunk_header_size: int) -> 'ChunkHeader':
        buffer = bytearray(chunk_header_size)
        ts_file_input.read(buffer, offset)
        buffer = bytes(buffer)
        chunk_type = buffer[0]
        measurement_id = ReadWriteIOUtils.read_var_int_string(buffer[1:])
        data_size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer[1 + len(measurement_id):])
        data_type = TSDataType.deserialize(buffer[1 + len(measurement_id) + 4:])
        compression_type = CompressionType.deserialize(buffer[1 + len(measurement_id) + 4 + TSDataType.get_serialized_size():])
        encoding_type = TSEncoding.deserialize(buffer[1 + len(measurement_id) + 4 + TSDataType.get_serialized_size() + CompressionType.get_serialized_size():])
        return ChunkHeader(chunk_type, measurement_id, data_size, buffer[:].index(b'\0'), data_type, compression_type, encoding_type)

    def get_serialized_size(self) -> int:
        return self.serialized_size

    @property
    def measurement_id(self):
        return self._measurement_id

    @measurement_id.setter
    def measurement_id(self, value: str):
        self._measurement_id = value

    @property
    def data_size(self):
        return self._data_size

    @data_size.setter
    def data_size(self, value: int):
        self._data_size = value

    @property
    def data_type(self):
        return self._data_type

    @data_type.setter
    def data_type(self, value: 'TSDataType'):
        self._data_type = value

    @property
    def compression_type(self):
        return self._compression_type

    @compression_type.setter
    def compression_type(self, value: 'CompressionType'):
        self._compression_type = value

    @property
    def encoding_type(self):
        return self._encoding_type

    @encoding_type.setter
    def encoding_type(self, value: 'TSEncoding'):
        self._encoding_type = value

    def serialize_to(self) -> bytes:
        buffer = bytearray()
        buffer.extend([self.chunk_type])
        buffer.extend(measurement_id.encode('utf-8'))
        buffer.extend(ReadWriteForEncodingUtils.u_var_int_size(self.data_size).to_bytes())
        buffer.extend(TSDataType.serialize(self.data_type))
        buffer.extend(CompressionType.serialize(self.compression_type))
        buffer.extend(TSEncoding.serialize(self.encoding_type))
        return bytes(buffer)

    def serialize_to_buffer(self, buffer: bytearray) -> int:
        buffer.append(self.chunk_type)
        buffer.extend(measurement_id.encode('utf-8'))
        buffer.extend(ReadWriteForEncodingUtils.u_var_int_size(self.data_size).to_bytes())
        buffer.extend(TSDataType.serialize(self.data_type))
        buffer.extend(CompressionType.serialize(self.compression_type))
        buffer.extend(TSEncoding.serialize(self.encoding_type))
        return len(buffer)

    @property
    def num_of_pages(self):
        return self._num_of_pages

    @num_of_pages.setter
    def num_of_pages(self, value: int):
        self._num_of_pages = value

    @property
    def serialized_size(self) -> int:
        return self._serialized_size

    @serialized_size.setter
    def serialized_size(self, value: int):
        self._serialized_size = value

    def merge_chunk_header(self, chunk_header: 'ChunkHeader') -> None:
        self.data_size += chunk_header.data_size
        self.num_of_pages += chunk_header.num_of_pages

    def set_data_size(self, data_size: int) -> None:
        self.data_size = data_size

    @property
    def chunk_type(self):
        return self._chunk_type

    @chunk_type.setter
    def chunk_type(self, value: bytes):
        self._chunk_type = value

    def increase_page_nums(self, i: int) -> None:
        self.num_of_pages += i


class TSDataType:
    @staticmethod
    def get_serialized_size() -> int:
        # TO DO: implement the method
        pass

    @staticmethod
    def deserialize(input_stream: bytes) -> 'TSDataType':
        # TO DO: implement the method
        pass


class CompressionType:
    @staticmethod
    def get_serialized_size() -> int:
        # TO DO: implement the method
        pass

    @staticmethod
    def serialize(self) -> bytes:
        # TO DO: implement the method
        pass

    @staticmethod
    def deserialize(input_stream: bytes) -> 'CompressionType':
        # TO DO: implement the methods


class TSEncoding:
    @staticmethod
    def get_serialized_size() -> int:
        # TO DO: implement the method
        pass

    @staticmethod
    def serialize(self) -> bytes:
        # TO DO: implement the method
        pass

    @staticmethod
    def deserialize(input_stream: bytes) -> 'TSEncoding':
        # TO DO: implement the methods


class TsFileInput:
    def read(self, buffer: bytearray, offset: int) -> None:
        # TO DO: implement the method
        pass
