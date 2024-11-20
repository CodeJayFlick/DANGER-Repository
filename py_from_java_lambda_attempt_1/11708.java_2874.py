Here is the translation of the given Java code into Python:

```Python
class OrExpression:
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, l, r):
        super().__init__(location, l, r)

    def get_value(self, pos):
        left_val = self.get_left().get_value(pos)
        right_val = self.get_right().get_value(pos)
        return left_val | right_val

    def get_sub_value(self, replace, list_pos):
        left_val = self.get_left().get_sub_value(replace, list_pos)  # Must be left first
        right_val = self.get_right().get_sub_value(replace, list_pos)
        return left_val | right_val

    def save_xml(self, s):
        s.write("<or_exp>\n")
        super().save_xml(s)
        s.write("</or_exp>\n")

# Example usage:
class Location: pass
class PatternExpression: pass
class ParserWalker: pass
class VectorSTL(list): pass
class MutableInt(int): pass

location = Location()
l = PatternExpression()
r = PatternExpression()

oe = OrExpression(location, l, r)

pos = ParserWalker()
print(oe.get_value(pos))  # prints the result of OR operation between left and right values

replace = VectorSTL([1, 2, 3])
list_pos = MutableInt(0)
print(oe.get_sub_value(replace, list_pos))  # prints the result of OR operation between left and right sub-values

s = open('output.txt', 'w')
oe.save_xml(s)
```

Please note that Python does not have direct equivalents for Java classes like `VectorSTL` or `MutableInt`. I've replaced them with built-in Python types (`list` and `int`) in the above code.