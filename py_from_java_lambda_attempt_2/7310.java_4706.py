Here is the equivalent Python code:

```Python
class Apple8900Constants:
    MAGIC = "8900"
    MAGIC_BYTES = bytes(MAGIC.encode())
    MAGIC_LENGTH = len(MAGIC)

    FORMAT_ENCRYPTED = 3  # AES-128-CBC, 0x837 key and all zero IV
    FORMAT_PLAIN = 4

    AES_KEY_STRING = "188458A6D15034DFE386F23B61D43774"
    AES_KEY_BYTES = bytes(AES_KEY_STRING.encode())

    AES_IV_ZERO_BYTES = bytearray(16)
```

Note that Python does not have a direct equivalent to Java's `public final static` keyword. In Python, we can use the class itself as if it were an object (since classes are objects in Python), and define constants within the class definition.