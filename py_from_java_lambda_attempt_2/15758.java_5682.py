Here is the translation of the Java code to Python:
```
class Pair:
    def __init__(self, key, value):
        self.key = key
        self.value = value

    @property
    def key(self):
        return self.key

    @property
    def value(self):
        return self.value

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, Pair) or type(self) != type(other):
            return False
        else:
            return self.key == other.key and self.value == other.value

    def __hash__(self):
        return hash((self.key, self.value))
```
Note that I've used Python's built-in `property` decorator to create read-only properties for the `key` and `value` attributes. This is equivalent to Java's getter methods.

I've also replaced the `equals()` method with a special method in Python called `__eq__()`, which is used to implement object equality checking. The rest of the code remains similar, but with some minor adjustments to fit Python's syntax and semantics.