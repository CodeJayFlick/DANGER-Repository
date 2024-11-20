Here is the translation of the given Java code into equivalent Python:

```Python
class XmlUtils:
    def __init__(self):
        pass  # utils class

    @staticmethod
    def a_v(s, attr, val):
        s.write(' ' + attr + '="')
        xml_escape(s, val)
        s.write('"')

    @staticmethod
    def a_v_i(s, attr, val):
        s.write(' ' + attr + '="')
        s.write(str(val))
        s.write('"')

    @staticmethod
    def a_v_u(s, attr, val):
        s.write(' ' + attr + '="0x')
        s.write(hex(val)[2:])
        s.write('"')

    @staticmethod
    def a_v_b(s, attr, val):
        s.write(' ' + attr + '="')
        if val:
            s.write("true")
        else:
            s.write("false")
        s.write('"')

    @staticmethod
    def decode_boolean(bool_string):
        if bool_string is None or len(bool_string) == 0:
            return False

        first_char = bool_string[0]
        if first_char in ['t', '1', 'y']:
            return True
        else:
            return False

    @staticmethod
    def decode_unknown_int(int_string):
        if int_string is None:
            return 0

        # special case
        if "0" == int_string:
            return 0

        bi = None
        if int_string.startswith("0x"):
            bi = int(str(int.from_bytes(bytes.fromhex(int_string[2:]), 'big'), 16)
        elif int_string.startswith("0"):
            bi = int(str(int.from_bytes(bytes.fromhex(int_string[1:]), 'big'), 8)
        else:
            bi = int(int_string)

        return bi

    @staticmethod
    def decode_unknown_long(long_string):
        if long_string is None:
            return 0

        # special case
        if "0" == long_string:
            return 0

        bi = None
        if long_string.startswith("0x"):
            bi = int(str(int.from_bytes(bytes.fromhex(long_string[2:]), 'big'), 16)
        elif long_string.startswith("0"):
            bi = int(str(int.from_bytes(bytes.fromhex(long_string[1:]), 'big'), 8)
        else:
            bi = int(long_string)

        return bi

    @staticmethod
    def xml_escape(s, str):
        for i in range(len(str)):
            c = str[i]
            if c == '<':
                s.write('&lt;')
            elif c == '>':
                s.write('&gt;')
            elif c == '"':
                s.write('&quot;')
            elif c == "'":
                s.write('&apos;')
            elif c == '&':
                s.write('&amp;')
            else:
                s.write(c)
```

Please note that Python does not have a direct equivalent to Java's `PrintStream`. In this translation, I used the built-in string methods (`write`, `append`) and did not use any external libraries.