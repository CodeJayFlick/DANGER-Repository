Here is the translation of the given Java code into Python:

```Python
class MDEncodedNumber:
    def __init__(self):
        self.number = ""
        self.value = None

    def get_value(self):
        return self.value

    def set_value(self, value):
        self.value = value

    def insert(self, builder):
        dmang.insert_spaced_string(builder, str(self.value))

class MDException(Exception):
    pass
```

Note that Python does not have direct equivalent of Java's `BigInteger` class. However, you can use the built-in `int` or `long` types for smaller integers and consider using a library like `gmpy2` if you need to work with very large numbers.

Also note that in Python, we don't need to explicitly define getters and setters as they are not enforced by the language. The above code is simplified version of Java's equivalent code.