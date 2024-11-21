import struct

class MetadataIndexEntryV2:
    def __init__(self):
        pass

    @classmethod
    def deserialize_from(cls, buffer: bytes) -> 'MetadataIndexEntryV2':
        name = buffer.decode().split('\x00')[0]
        offset = int.from_bytes(buffer[4:], byteorder='little')
        return MetadataIndexEntry(name, offset)

class MetadataIndexEntry:
    def __init__(self, name: str, offset: int):
        self.name = name
        self.offset = offset

def read_string(buffer: bytes) -> str:
    return buffer.decode().split('\x00')[0]

def read_long(buffer: bytes) -> int:
    return int.from_bytes(buffer[4:], byteorder='little')
