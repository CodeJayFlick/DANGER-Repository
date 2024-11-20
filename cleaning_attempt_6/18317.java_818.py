import io
from typing import Union


class ChunkHeaderV2:
    def __init__(self):
        pass

    @staticmethod
    def deserialize_from(input_stream: io.BytesIO, marker_read: bool) -> dict:
        if not marker_read:
            input_stream.read(1)
        
        measurement_id = read_string(input_stream)
        data_size = int.from_bytes(input_stream.read(4), 'big')
        data_type = TSDataType.deserialize(int.from_bytes(input_stream.read(2), 'big'))
        num_of_pages = int.from_bytes(input_stream.read(4), 'big')
        compression_type = CompressionType.deserialize(int.from_bytes(input_stream.read(2), 'big'))
        encoding_type = TSEncoding.deserialize(int.from_bytes(input_stream.read(2), 'big'))

        return {
            "measurement_id": measurement_id,
            "data_size": data_size,
            "data_type": data_type,
            "num_of_pages": num_of_pages,
            "compression_type": compression_type,
            "encoding_type": encoding_type
        }

    @staticmethod
    def deserialize_from_tsfile(input: io.BytesIO, offset: int, chunk_header_size: int, marker_read: bool) -> dict:
        if not marker_read:
            offset += 1

        buffer = bytearray(chunk_header_size)
        input.readinto(buffer)

        measurement_id_length = int.from_bytes(buffer[:4], 'big')
        measurement_id = read_string(input, buffer[4:4 + measurement_id_length])
        data_size = int.from_bytes(buffer[4 + measurement_id_length:], 8, 'big')

        return {
            "measurement_id": measurement_id,
            "data_size": data_size
        }

    @staticmethod
    def get_serialized_size(measurement_id: str) -> int:
        return len(MetaMarker.CHUNK_HEADER.encode()) \
               + len(str(len(measurement_id)).encode()) \
               + len(measurement_id.encode(TSFileConfig.STRING_CHARSET)) \
               + 4 \
               + 2 \
               + 2 \
               + 2


def read_string(input: io.BytesIO) -> str:
    length = int.from_bytes(input.read(4), 'big')
    return input.read(length).decode()


class TSDataType:
    @staticmethod
    def deserialize(data_type_code: int) -> Union[int, float]:
        # TO DO: implement the deserialization logic for data type code


class CompressionType:
    @staticmethod
    def deserialize(compression_type_code: int) -> str:
        # TO DO: implement the deserialization logic for compression type code


class TSEncoding:
    @staticmethod
    def deserialize(encoding_type_code: int) -> str:
        # TO DO: implement the deserialization logic for encoding type code

