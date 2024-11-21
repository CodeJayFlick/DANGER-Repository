Here is the translation of the Java code into Python:

```Python
class DebugSymbol:
    def __init__(self):
        self.length = None
        self.type = None
        self.name = None
        self.section = None
        self.offset = None

    def process_debug_symbol(self, length, type):
        self.length = length
        self.type = type

    @property
    def get_length(self):
        return self.length

    @property
    def get_type(self):
        return self.type

    @property
    def get_name(self):
        return self.name

    @property
    def get_section(self):
        return self.section

    @property
    def get_offset(self):
        return self.offset


# Example usage:
symbol = DebugSymbol()
symbol.process_debug_symbol(10, 20)
print(symbol.get_length)  # prints: 10
print(symbol.get_type)     # prints: 20
```

Please note that Python does not have direct equivalent of Java's `public`, `protected` and other access modifiers. In this translation, I've used the concept of properties to mimic some of these behaviors.