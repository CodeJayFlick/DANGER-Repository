Here is the translation of the Java code to Python:
```
class XorExpression(BinaryExpression):
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, l, r):
        super().__init__(location, l, r)

    def get_value(self, pos):
        left_val = self.get_left().get_value(pos)
        right_val = self.get_right().get_value(pos)
        return left_val ^ right_val

    def get_sub_value(self, replace, list_pos):
        left_val = self.get_left().get_sub_value(replace, list_pos)  # Must be left first
        right_val = self.get_right().get_sub_value(replace, list_pos)
        return left_val ^ right_val

    def save_xml(self, s):
        s.write("<xor_exp>\n")
        super().save_xml(s)
        s.write("</xor_exp>\n")

class BinaryExpression:
    pass
```
Note that I did not translate the `Location`, `PatternExpression`, `ParserWalker`, `VectorSTL`, and `MutableInt` classes, as they are likely specific to the Ghidra framework and may require additional context or implementation details. The above Python code assumes a basic understanding of object-oriented programming in Python.

Also, I used the built-in `write()` method for printing to the stream instead of using `append()`, which is more idiomatic in Python.