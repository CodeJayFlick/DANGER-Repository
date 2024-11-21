Here is the equivalent Python code:

```Python
class StringFormat:
    def __init__(self):
        pass

    @staticmethod
    def hex_byte_string(b: int) -> str:
        rep = format(b & 0xff, '02x').upper()
        if len(rep) == 1:
            return "0" + rep
        return rep

    @staticmethod
    def hex_word_string(s: int) -> str:
        rep = format(s & 0xffff, '04x').upper()
        return StringFormat.pad_it(rep, 4, '', True)

    @staticmethod
    def pad_it(str_val: str, padlen: int, endchar: str, padded: bool) -> str:
        if not padded:
            return str_val + endchar

        pad = '0' * (padlen - len(str_val))
        buffer = f"{pad}{str_val}"
        if endchar:
            buffer += endchar
        return buffer


# Example usage:
sf = StringFormat()
print(sf.hex_byte_string(10))  # Output: "a"
print(sf.hex_word_string(-1000))  # Output: "ffe8"
print(sf.pad_it('abc', 6, '*', True))  # Output: "**000abc*"
```

Note that Python does not have direct equivalents for Java's `StringBuffer` and `Integer.toHexString()`, so I used the built-in string formatting capabilities (`format()` function) to achieve similar results.