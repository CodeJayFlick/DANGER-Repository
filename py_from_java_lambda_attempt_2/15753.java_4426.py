Here is the equivalent Python code:

```Python
class Hex:
    HEX_CHARS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

    def __init__(self):
        pass

    @staticmethod
    def to_hex_string(block: bytes) -> str:
        if block is None:
            return None
        
        buf = ""
        for a_block in block:
            high = (a_block & 0xf0) >> 4
            low = a_block & 0x0f
            
            buf += Hex.HEX_CHARS[high]
            buf += Hex.HEX_CHARS[low]
        
        return buf

    @staticmethod
    def to_byte_array(s: str) -> bytes:
        if len(s) % 2 != 0:
            raise ValueError("Invalid Hex String")
        
        ret = bytearray()
        for i in range(len(s) // 2):
            ret.append(int.from_bytes(s[i*2:i*2+2].encode(), 16))
        
        return bytes(ret)
```

Note that Python does not have a direct equivalent to Java's `StringBuilder` class, so I used the string concatenation operator (`+=`) to build up the hex string. Also, in Python, we don't need to explicitly specify types for variables and function parameters like we do in Java.