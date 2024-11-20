Here is the translation of the given Java code into Python:

```Python
class PatternlessSymbol:
    def __init__(self):
        self.patexp = ConstantValue(0)

    def get_pattern_expression(self):
        return self.patexp


class SpecificSymbol:
    pass


class ConstantValue:
    def __init__(self, value):
        self.value = value

# Example usage
ps = PatternlessSymbol()
print(ps.get_pattern_expression().value)  # prints: 0
```

Please note that Python does not have direct equivalent of Java's abstract classes and interfaces. In this translation, I've used a regular class for `PatternlessSymbol` as it seems to be an implementation detail rather than an interface or abstract class in the original code.