Here is the translation of the Java code to Python:
```
import decimal

class StringUtils:
    all_bytes = bytes(range(-128, 128))
    byte_to_chars = [chr(b) for b in range(256)]

    @classmethod
    def consistent_to_string(cls, decimal):
        if decimal is None:
            return None
        try:
            return str(decimal.to_plain_string())
        except Exception as e:
            pass
        return str(decimal)

    @classmethod
    def fix_decimal_exponent(cls, d_string):
        e_pos = d_string.find("E")
        if e_pos == -1:
            e_pos = d_string.find("e")
        if e_pos != -1 and len(d_string) > e_pos + 1:
            maybe_minus_char = d_string[e_pos + 1]
            if maybe_minus_char not in ['-', '+']:
                buf = StringBuffer(len(d_string))
                buf.append(d_string[:e_pos + 1])
                buf.append('+')
                buf.append(d_string[e_pos + 1:])
                return str(buf)
        return d_string

class StringBuffer:
    def __init__(self, length):
        self.length = length
        self.buf = [None] * (length + 1)

    def append(self, s):
        for c in s:
            if len(self.buf) <= self.length:
                self.buf.append(c)
            else:
                raise ValueError("Buffer overflow")

    def __str__(self):
        return ''.join(self.buf[:self.length])
```
Note that I had to create a `StringBuffer` class in Python, as there is no built-in equivalent. Also, the `BigDecimal.to_plain_string()` method does not exist in Python's decimal module, so I used the `str()` function instead.

Also, please note that this translation may not be perfect and some parts of the code might not work exactly as they do in Java.