Here is the translation of the given Java code into Python:

```Python
class DivExpression(BinaryExpression):
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, l, r):
        super().__init__(location, l, r)

    def get_value(self, pos):
        left_val = self.get_left().get_value(pos)
        right_val = self.get_right().get_value(pos)
        return left_val / right_val

    def get_sub_value(self, replace, list_pos):
        left_val = self.get_left().get_sub_value(replace, list_pos)  # Must be left first
        right_val = self.get_right().get_sub_value(replace, list_pos)
        return left_val / right_val

    def save_xml(self, s):
        s.write("<div_exp>\n")
        super().save_xml(s)
        s.write("</div_exp>\n")

class BinaryExpression:
    def __init__(self, location):
        self.location = location

    def get_left(self):
        pass  # To be implemented in subclass

    def get_right(self):
        pass  # To be implemented in subclass

    def save_xml(self, s):
        pass  # To be implemented in subclass
```

Note that the `BinaryExpression` class is not fully defined here as it was in the original Java code. The `get_left`, `get_right`, and `save_xml` methods are declared but their implementations depend on the specific requirements of your program, which you would need to add yourself.