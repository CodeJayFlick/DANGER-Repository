Here is the translation of the Java code to Python:

```Python
class Pair:
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def __hash__(self):
        return hash((self.left, self.right))

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return (self.left == other.left and self.right == other.right)
        else:
            return NotImplemented

    def __str__(self):
        return f"<{self.left}, {self.right}>"
```

Note that Python does not have a built-in equivalent to Java's generics. The `Pair` class in this translation is defined without type parameters, and the `left` and `right` attributes can hold values of any type.