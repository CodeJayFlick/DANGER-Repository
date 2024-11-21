Here is the translation of the given Java code into Python:

```Python
class ContextOp:
    def __init__(self, location):
        self.location = location

    @property
    def patexp(self):
        return self._patexp

    @patexp.setter
    def patexp(self, value):
        if not isinstance(value, PatternExpression):
            raise ValueError("Invalid pattern expression")
        self._patexp = value

    @property
    def num(self):
        return self._num

    @num.setter
    def num(self, value):
        self._num = value

    @property
    def shift(self):
        return self._shift

    @shift.setter
    def shift(self, value):
        self._shift = value

    @property
    def mask(self):
        return self._mask

    @mask.setter
    def mask(self, value):
        self._mask = value

    def __init__(self, location, startbit, endbit, patexp):
        self.location = location
        self.num = 0
        self.shift = 0
        self.mask = 0
        self.patexp = None
        if patexp is not None:
            self.patexp = patexp

    def dispose(self):
        PatternExpression.release(self.patexp)

    def apply(self, pos):
        val = int(self.patexp.get_value(pos))
        val <<= self.shift
        pos.parser_context.set_context_word(self.num, val, self.mask)

    def validate(self):
        values = []
        if self.patexp is not None:
            self.patexp.list_values(values)
            for i in range(len(values)):
                value = values[i]
                if isinstance(value, OperandValue) and not value.is_constructor_relative():
                    raise SleighError(f"{value.name}: cannot be used in context expression", value.location)

    def save_xml(self, s):
        s.write("<context_op")
        s.write(f" i=\"{self.num}\"")
        s.write(f" shift=\"{self.shift}\"")
        s.write(f" mask=\"0x{Utils.to_unsigned_int_hex(self.mask)}\"")
        s.write(">\n")
        if self.patexp is not None:
            self.patexp.save_xml(s)
        s.write("</context_op>\n")

    def restore_xml(self, el, trans):
        self.num = XmlUtils.decode_unknown_int(el.get_attribute_value("i"))
        self.shift = XmlUtils.decode_unknown_int(el.get_attribute_value("shift"))
        self.mask = XmlUtils.decode_unknown_int(el.get_attribute_value("mask"))
        child = el[0]
        if child is not None:
            self.patexp = PatternExpression.restore_expression(child, trans)
```

Please note that this translation assumes the existence of certain classes and functions (like `PatternExpression`, `OperandValue`, `SleighError`, etc.) which are not provided in your code.