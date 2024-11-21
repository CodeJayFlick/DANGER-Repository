Here is the translation of the given Java code into equivalent Python:

```Python
class AndExpression:
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, l, r):
        super().__init__(location, l, r)

    def get_value(self, pos):
        left_val = self.get_left().get_value(pos)
        right_val = self.get_right().get_value(pos)
        return left_val & right_val

    def get_sub_value(self, replace, list_pos):
        left_val = self.get_left().get_sub_value(replace, list_pos)  # Must be left first
        right_val = self.get_right().get_sub_value(replace, list_pos)
        return left_val & right_val

    def save_xml(self, s):
        s.write("<and_exp>\n")
        super().save_xml(s)
        s.write("</and_exp>\n")

class BinaryExpression:
    pass  # This class is not fully implemented in the given Java code.

class PatternExpression:
    pass  # This class is not fully implemented in the given Java code.
```

Please note that this translation assumes that `Location`, `ParserWalker`, `VectorSTL`, and `MutableInt` are Python classes or modules, which they may not be.