Here is the translation of the given Java code into equivalent Python:

```Python
class ValueMapSymbol:
    def __init__(self):
        self.valuetable = []
        self.tableisfilled = False

    def get_map(self):
        return [v for v in self.valuetable]

    def check_table_fill(self, min_value=None, max_value=None):
        if not (min_value >= 0 and max_value < len(self.valuetable)):
            self.tableisfilled = False
        else:
            for element in self.valuetable:
                if element == 0xBADBEEF:
                    self.tableisfilled = False

    def resolve(self, walker=None, debug_logger=None):
        if not self.tableisfilled:
            ind = walker.get_pattern_value()
            if (ind >= len(self.valuetable) or
               ind < 0 or valuetable[ind] == 0xBADBEEF):
                errmsg = f"No corresponding entry in valuetable {self.name}>, index={ind}"
                debug_logger.append(errmsg + "\n")
                raise UnknownInstructionException(errmsg)
        return None

    def get_fixed_handle(self, hand=None, walker=None):
        ind = int(walker.get_pattern_value())
        # Entry has already been tested for null by the resolve routine
        hand.space = walker.get_const_space()
        hand.offset_space = None  # Not a dynamic variable
        hand.offset_offset = self.valuetable[ind]
        hand.size = 0  # Cannot provide size

    def print(self, walker=None):
        ind = int(walker.get_pattern_value())
        # ind is already known to be a valid array index via resolve
        val = self.valuetable[ind]
        if val >= 0:
            res = f"0x{val:08X}"
        else:
            res = f"-0x{abs(val):08X}"
        return res

    def restore_xml(self, parser=None, sleigh_language=None):
        el = parser.start("valuemap_sym")
        self.patval = PatternExpression.restore_expression(parser, sleigh_language)
        values = []
        valuetab = None
        while (valuetab := parser.soft_start("valuetab")) is not None:
            values.append(valuetab.get_attribute("val"))
            parser.end(valuetab)
        self.valuetable = [SpecXmlUtils.decode_long(v) for v in values]
        self.check_table_fill()
        parser.end(el)

class UnknownInstructionException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation.