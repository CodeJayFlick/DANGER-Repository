Here is the translation of the Java code to Python:
```python
import io

class ChunkGroupFooterV2:
    def __init__(self):
        pass

    @staticmethod
    def deserialize_from(input_stream: bytes, marker_read: bool) -> dict:
        if not marker_read:
            marker = input_stream.read(1)
            if marker != MetaMarker.CHUNK_GROUP_HEADER:
                MetaMarker.handle_unexpected_marker(marker)

        device_id_length = int.from_bytes(io.BytesIO(input_stream).read(), byteorder='little')
        device_id = io.BytesIO(input_stream).read(device_id_length).decode('utf-8')

        data_size = int.from_bytes(io.BytesIO(input_stream).read(8), byteorder='little')
        num_chunks = int.from_bytes(io.BytesIO(input_stream).read(4), byteorder='little')

        return {'device_id': device_id, 'data_size': data_size, 'num_chunks': num_chunks}

    @staticmethod
    def deserialize_from_tsfile_input(ts_file_input: bytes, offset: int, marker_read: bool) -> dict:
        if not marker_read:
            offset += 1

        buffer = io.BytesIO()
        ts_file_input.seek(offset)
        buffer.write(ts_file_input.read(4))
        buffer.flip()

        size = int.from_bytes(buffer.getvalue(), byteorder='little')
        buffer = io.BytesIO()
        ts_file_input.seek(offset + Integer.BYTES)
        buffer.write(ts_file_input.read(get_serialized_size(size)))
        buffer.flip()

        device_id_length = int.from_bytes(buffer.getvalue()[:4], byteorder='little')
        device_id = buffer.getvalue()[4:device_id_length+4].decode('utf-8')

        data_size = int.from_bytes(buffer.getvalue()[device_id_length+4:], byteorder='little')
        num_chunks = int.from_bytes(buffer.getvalue()[-4:], byteorder='little')

        return {'device_id': device_id, 'data_size': data_size, 'num_chunks': num_chunks}

    @staticmethod
    def get_serialized_size(device_id_length: int) -> int:
        return device_id_length + 8 + 4

MetaMarker = None  # define MetaMarker class or variable here
```
Note that I've used the `io` module to work with bytes and file-like objects, as well as some Python-specific constructs like dictionaries and bytearrays. The logic of the code remains largely unchanged from the Java original.