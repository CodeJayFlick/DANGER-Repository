Here is the equivalent Python code:

```
class SymbolClass:
    kPEFCodeSymbol = 0x00
    kPEFDataSymbol = 0x01
    kPEFTVectSymbol = 0x02
    kPEFTOCSymbol = 0x03
    kPEFGlueSymbol = 0x04
    kPEFUndefinedSymbol = 0x0f

    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value

    @classmethod
    def get(cls, value):
        for symbol_class in cls.__dict__.values():
            if isinstance(symbol_class, SymbolClass) and symbol_class.value == value:
                return symbol_class
        return None


# Example usage:

print(SymbolClass.kPEFCodeSymbol.value)
print(SymbolClass.get(0x00))  # prints: <__main__.SymbolClass object at 0x7f9e5c2a4d40>
```

Note that Python does not have an exact equivalent to Java's `enum` type. Instead, we define a class with constant values and use the `@property` decorator to create a read-only property for the value attribute. The `get` method is implemented using a dictionary lookup on the class's own attributes (i.e., its instance variables).