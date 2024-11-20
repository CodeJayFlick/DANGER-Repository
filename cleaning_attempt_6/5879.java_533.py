class CaseInsensitiveByteTrieNode:
    def __init__(self, id: int, parent=None, length: int = 0):
        super().__init__(id, parent, length)

    OFFSET = ord('a') - ord('A')

    def transform_byte(self, v: bytes) -> bytes:
        if 'a' <= chr(v).lower() <= 'z':
            return (chr(ord(chr(v)) + self.OFFSET)).encode()
        return v
