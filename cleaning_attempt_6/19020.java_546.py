from typing import Tuple

class ContentsId:
    pass  # define this class as needed in your application

class Key:
    pass  # define this class as needed in your application

class ByteString:  # note that this is not a direct equivalent, but rather an approximation
    def __init__(self, value):
        self.value = value

def key_with_bytes(key: Key, contents_id: ContentsId, type: bytes, value: ByteString) -> Tuple[Key, ContentsId, int, ByteString]:
    return (key, contents_id, type, value)

class KeyWithBytes:
    def __init__(self, key: Key, contents_id: ContentsId, type: int, value: ByteString):
        self.key = key
        self.contents_id = contents_id
        self.type = type
        self.value = value

    @property
    def as_key_type(self) -> Tuple[Key, ContentsId, int]:
        return (self.key, self.contents_id, self.type)
