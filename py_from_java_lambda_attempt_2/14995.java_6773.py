Here is the translation of the given Java code into Python:

```Python
class Mass:
    def __init__(self, value):
        self.value = value
        self.title = f"{value:.2f} kg"

    def greater_than(self, other):
        return self.value > other.value

    def smaller_than(self, other):
        return self.value < other.value

    def greater_than_or_eq(self, other):
        return self.value >= other.value

    def smaller_than_or_eq(self, other):
        return self.value <= other.value

    def __str__(self):
        return self.title
```

Note that Python does not have an exact equivalent to Java's `@EqualsAndHashCode` annotation. The `__eq__`, `__lt__`, etc., methods would need to be implemented manually in the Python class if you want to use them for comparison operations like `==`, `<`, etc.

Also, note that I used f-strings (formatted strings) in the constructor to create the title string. This is a feature available from Python 3.6 onwards. If you're using an earlier version of Python, you can use regular concatenation or the `%` operator instead.