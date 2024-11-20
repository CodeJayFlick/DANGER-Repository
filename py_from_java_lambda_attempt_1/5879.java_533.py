Here is the translation of the given Java code into Python:

```Python
class CaseInsensitiveByteTrieNode:
    def __init__(self, id: int, parent=None, length: int = 0):
        super().__init__(id, parent, length)

    OFFSET = ord('a') - ord('A')

    def transform_byte(self, v: bytes) -> bytes:
        if 'a' <= chr(v).lower() <= 'z':
            return (chr(ord(chr(v)) + self.OFFSET)).encode()
        return v
```

Note that Python does not have a direct equivalent to Java's generics. In this translation, I've removed the type parameter `<T>` as it is not necessary in Python. Also, note that `@Override` annotation is not needed in Python because method overriding is done by name and signature of methods.