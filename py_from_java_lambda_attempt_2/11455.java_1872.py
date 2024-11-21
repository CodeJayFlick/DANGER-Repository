Here is the translation of the given Java code into Python:

```Python
class Constant:
    def __init__(self, v):
        self.val = v

    def long_value(self, buf=None, off=0):
        return self.val

    def length(self, buf=None, off=0):
        return 0


# Example usage:
c = Constant(123)
print(c.long_value())  # prints: 123
```

Note that Python does not have direct equivalents for Java's `public` and `private` access modifiers. In Python, everything is public by default (i.e., it can be accessed from anywhere), but you can use double underscore prefix (`__`) to create a "private" attribute which cannot be directly accessed outside the class.