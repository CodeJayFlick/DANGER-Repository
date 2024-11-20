Here is the translation of the given Java code into equivalent Python:

```Python
class SubExpression:
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, l, r):
        super().__init__(location, l, r)

    def get_value(self, pos):
        left_val = self.get_left().get_value(pos)
        right_val = self.get_right().get_value(pos)
        return left_val - right_val

    def get_sub_value(self, replace, list_pos):
        left_val = self.get_left().get_sub_value(replace, list_pos)  # Must be left first
        right_val = self.get_right().get_sub_value(replace, list_pos)
        return left_val - right_val

    def save_xml(self, s):
        s.write("<sub_exp>\n")
        super().save_xml(s)
        s.write("</sub_exp>\n")

# Note: Python does not have direct equivalent of Java's VectorSTL and MutableInt.
```

Please note that in the above code:

- `get_left()` and `get_right()` are assumed to be methods which return left and right operands respectively. Similarly, `save_xml` method is also assumed to exist.

- In Python, we don't have direct equivalent of Java's VectorSTL and MutableInt classes. So I didn't include them in the translation as they seem to be used for some specific purpose (like storing values or positions) which can be achieved using built-in data structures like lists or dictionaries in Python.