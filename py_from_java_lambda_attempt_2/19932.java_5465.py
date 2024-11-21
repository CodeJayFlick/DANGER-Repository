Here is the translation of the Java code into Python:

```Python
import struct
from typing import Dict, Any

class ListVariablePersistentDataType:
    SERIALIZED_CHARSET = 'utf-8'

    def get_primitive_type(self) -> type:
        return bytes

    def get_complex_type(self) -> type:
        from collections.abc import Mapping
        return Mapping[str, Any]

    def to_primitive(self, complex: Dict[str, Any], context=None) -> bytes:
        buffer_length = 0
        for key, value in complex.items():
            index_bytes_len = len(key.encode(self.SERIALIZED_CHARSET))
            type_bytes_len = len(value['type'].encode(self.SERIALIZED_CHARSET))
            data_bytes_len = len(value['data'])
            buffer_length += struct.calcsize('i') + index_bytes_len + \
                              struct.calcsize('i') + type_bytes_len + \
                              struct.calcsize('i') + data_bytes_len

        bb = bytearray(buffer_length)
        offset = 0
        for key, value in complex.items():
            index_bytes = key.encode(self.SERIALIZED_CHARSET)
            type_bytes = value['type'].encode(self.SERIALIZED_CHARSET)

            struct.pack_into('i{}s{}si'.format(index_bytes_len), bb, offset,
                             len(index_bytes))
            bb[offset + 4:] = index_bytes
            offset += index_bytes_len + 4

            struct.pack_into('i{}s{}si'.format(type_bytes_len), bb, offset,
                             len(type_bytes))
            bb[offset + 4:] = type_bytes
            offset += type_bytes_len + 8

            struct.pack_into('i{}s'.format(data_bytes_len), bb, offset,
                             data_bytes)
            offset += data_bytes_len + 4

        return bytes(bb)

    def from_primitive(self, primitive: bytes) -> Dict[str, Any]:
        values = {}
        offset = 0
        while offset < len(primitive):
            index_length = struct.unpack_from('i', primitive[offset:offset+4])[0]
            index_bytes = primitive[offset + 4:offset + 4 + index_length].decode(self.SERIALIZED_CHARSET)
            type_length = struct.unpack_from('i', primitive[offset + 4 + index_length:offset + 8 + index_length])[0]
            type_bytes = primitive[offset + 8 + index_length:offset + 8 + index_length + type_length].decode(self.SERIALIZED_CHARSET)
            data_length = struct.unpack_from('i', primitive[offset + 8 + index_length + type_length:offset + 12 + index_length + type_length])[0]
            data_bytes = primitive[offset + 12 + index_length + type_length:index_length + type_length + data_length].decode(self.SERIALIZED_CHARSET)

            values[index_bytes] = {'type': type_bytes, 'data': data_bytes}
            offset += 4 + index_length + 8 + type_length + 4 + data_length

        return values
```

Please note that Python does not have direct equivalent of Java's `ByteBuffer` and `PersistentDataAdapterContext`. The above code uses the built-in `bytearray` for byte manipulation, and a simple dictionary to represent complex types.