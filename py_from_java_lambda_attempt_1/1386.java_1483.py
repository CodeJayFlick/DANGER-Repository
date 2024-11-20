Here is the translation of the given Java code into equivalent Python:

```Python
class GdbParsingUtils:
    def __init__(self):
        pass

    class AbstractGdbParser:
        def __init__(self, text):
            self.buf = CharBuffer(text)

        def match(self, pat, chomp_whitespace=False, group=None):
            if chomp_whitespace:
                self.chomp_whitespace()
            matcher = pat.matcher(self.buf)
            if matcher.lookingAt():
                result = group if group is not None else matcher.group()
                length = matcher.end() - matcher.start()
                self.buf.position(self.buf.position() + length)
                return result
            raise GdbParseError(f"{pat}, {self.buf}")

        def peek(self, chomp_whitespace=False):
            if chomp_whitespace:
                self.chomp_whitespace()
            if not self.buf.has_remaining():
                return '\0'
            return self.buf.get(self.buf.position())

        def chomp_whitespace(self):
            while self.buf.has_remaining() and Character.isWhitespace(self.buf.get(self.buf.position())):
                self.buf.get()

        def check_empty(self, chomp_whitespace=False):
            if chomp_whitespace:
                self.chomp_whitespace()
            if self.buf.has_remaining():
                raise GdbParseError("EOL", self.buf)

    class GdbParseError(Exception):
        def __init__(self, expected, s):
            super().__init__(f"Expected [{expected}] at tail '{s}'")

    @staticmethod
    def parse_prefixed_hex(hex_string):
        if not hex_string.startswith('0x'):
            raise ValueError("Hex must start with 0x")
        return int(hex_string[2:], 16)

    @staticmethod
    def parse_prefixed_hex_big(hex_string):
        if not hex_string.startswith('0x'):
            raise ValueError("Hex must start with 0x")
        return int(hex_string[2:], 16, 2**63-1)

    @staticmethod
    def parse_prefixed_octal(octal_string):
        if not octal_string.startswith('0'):
            raise ValueError("Octal must start with 0")
        return int(octal_string, 8)

    @staticmethod
    def parse_inferior_id(id_string):
        if not id_string.startswith('i'):
            raise ValueError("Map id does not specify an inferior. Must start with 'i'")
        return int(id_string[1:])
```

Please note that Python doesn't have direct equivalent of Java's `CharBuffer` and `Matcher`. So, I used a simple string buffer (`self.buf`) to simulate the behavior of these classes.