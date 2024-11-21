Here is the translation of the Java code into Python:

```Python
class ChunkGroupHeader:
    MARKER = bytes([MetaMarker.CHUNK_GROUP_HEADER])

    def __init__(self, device_id):
        self.device_id = device_id
        self.serialized_size = self.get_serialized_size(device_id)

    @staticmethod
    def get_serialized_size(device_id):
        length = len(device_id.encode(TSFileConfig.STRING_CHARSET))
        return len(ChunkGroupHeader.MARKER) + ReadWriteForEncodingUtils.var_int_size(length) + length

    @classmethod
    def deserialize_from(cls, input_stream, marker_read=False):
        if not marker_read:
            marker = input_stream.read(1)
            if marker != ChunkGroupHeader.MARKER:
                MetaMarker.handle_unexpected_marker(marker)

        device_id = ReadWriteIOUtils.read_var_int_string(input_stream)
        return cls(device_id)

    @classmethod
    def deserialize_from_tsfile_input(cls, ts_file_input, offset, marker_read=False):
        offset += 1 if not marker_read else 0
        device_id = ts_file_input.read_var_int_string(offset)
        return cls(device_id)

    def get_serialized_size(self):
        return self.serialized_size

    @property
    def device_id(self):
        return self._device_id

    def serialize_to(self, output_stream):
        length = 0
        length += output_stream.write(ChunkGroupHeader.MARKER)
        length += ReadWriteIOUtils.write_var_int_string(self.device_id.encode(TSFileConfig.STRING_CHARSET), output_stream)
        return length

    def __str__(self):
        return f"ChunkGroupHeader{{'device_id': '{self._device_id}', 'serialized_size': {self.serialized_size}}}"
```

Note that this translation assumes the existence of `MetaMarker`, `TSFileConfig`, and other classes in Python, which are not defined here.