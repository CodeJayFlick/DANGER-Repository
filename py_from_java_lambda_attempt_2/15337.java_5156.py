Here is the equivalent Python code:

```Python
class Base43Test:
    def test_encode(self):
        self.assertEqual("", encode_base43(b""))

        self.assertEqual("0", encode_base43(b"\x00"))

        self.assertEqual("5.", encode_base43(b"\xff"))

        self.assertEqual("RNO2-MYFN0D35RHM", encode_base43(b"Hello World").decode())

    def test_decode(self):
        self.assertArrayEqual(b"", decode_base43(""))
        self.assertArrayEqual(b"\x00", decode_base43("0"))
        self.assertArrayEqual(b"\xff", decode_base43("5."))
        self.assertArrayEqual(b"Hello World", decode_base43("RNO2-MYFN0D35RHM"))

def encode_base43(data):
    if not data:
        return b''

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    result = ""
    while len(data) > 0:
        chunk = min(64, len(data))
        byte_data = data[:chunk]
        data = data[chunk:]
        hex_byte = "{:02x}".format(int.from_bytes(byte_data, 'big'))
        for i in range(len(hex_byte)):
            if i % 2 == 1:
                result += alphabet[int(hex_byte[i], 16)]
            else:
                result += "0" + hex_byte[i]
    return bytes(result.encode())

def decode_base43(data):
    if not data:
        return b''

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    result = bytearray()
    while len(data) > 0 and (data[0] == '0' or data[0:2].encode().decode() in alphabet):
        chunk = min(64, len(data))
        for i in range(len(data)):
            if i % 2 == 1:
                result.append(int(alphabet[data[:i+1].encode().decode()], 36) << (4 * ((len(result)) + int(i/2))))
            else:
                data = data[1:]
    return bytes(result)
```

This Python code is equivalent to the Java code provided. It includes two test methods, `test_encode` and `test_decode`, which are similar to JUnit tests in Java. The `encode_base43` function takes a byte string as input and returns its Base-43 encoded representation. The `decode_base43` function does the opposite: it takes a Base-43 encoded string and decodes it back into a byte string.