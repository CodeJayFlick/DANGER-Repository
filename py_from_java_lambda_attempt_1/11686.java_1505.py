Here is the translation of the given Java code into Python:

```Python
class ContextField:
    def __init__(self, location):
        self.startbit = None
        self.endbit = None
        self.signbit = False
        super().__init__(location)

    @property
    def start_bit(self):
        return self.startbit

    @start_bit.setter
    def start_bit(self, value):
        self.startbit = value

    @property
    def end_bit(self):
        return self.endbit

    @end_bit.setter
    def end_bit(self, value):
        self.endbit = value

    @property
    def sign_bit(self):
        return self.signbit

    @sign_bit.setter
    def sign_bit(self, value):
        self.signbit = value

    def gen_min_pattern(self, ops):
        return TokenPattern(self.location)

    def min_value(self):
        return 0

    def max_value(self):
        res = ~0
        res = Utils.zzz_zero_extend(res, (self.endbit - self.startbit))
        return res

    def __init__(self, location, sign_bit=False, start_bit=0, end_bit=0):
        super().__init__(location)
        self.sign_bit = sign_bit
        self.start_bit = start_bit
        self.end_bit = end_bit
        self.start_byte = start_bit // 8
        self.end_byte = end_bit // 8
        self.shift = 7 - (end_bit % 8)

    def get_value(self, pos):
        res = ExpressUtils.get_context_bytes(pos, self.start_byte, self.end_byte)
        res >>= self.shift
        if self.sign_bit:
            res = Utils.zzz_sign_extend(res, end_bit - start_bit)
        else:
            res = Utils.zzz_zero_extend(res, end_bit - start_bit)
        return res

    def __str__(self):
        return f"cf:{{{self.start_bit},{self.end_bit},{self.start_byte},{self.end_byte},{self.shift},{self.sign_bit}}}"

    def gen_pattern(self, val):
        return TokenPattern(self.location, val, self.start_bit, self.end_bit)

    def save_xml(self, s):
        s.write("<contextfield")
        if self.sign_bit:
            s.write(" signbit=\"true\"")
        else:
            s.write(" signbit=\"false\"")
        s.write(f" startbit=\"{self.start_bit}\" endbit=\"{self.end_bit}\"")
        s.write(f" startbyte=\"{self.start_byte}\" endbyte=\"{self.end_byte}\" shift=\"{self.shift}\"/>\n")

    def restore_xml(self, el, trans):
        self.sign_bit = XmlUtils.decode_boolean(el.get_attribute_value("signbit"))
        self.start_bit = int(XmlUtils.decode_unknown_int(el.get_attribute_value("startbit")))
        self.end_bit = int(XmlUtils.decode_unknown_int(el.get_attribute_value("endbit")))
        self.start_byte = int(XmlUtils.decode_unknown_int(el.get_attribute_value("startbyte")))
        self.end_byte = int(XmlUtils.decode_unknown_int(el.get_attribute_value("endbyte")))
        self.shift = int(XmlUtils.decode_unknown_int(el.get_attribute_value("shift")))

class TokenPattern:
    def __init__(self, location):
        pass

# This class is not implemented in the given Java code
```

Note that I've used Python's built-in `property` decorator to create getter and setter methods for each attribute.