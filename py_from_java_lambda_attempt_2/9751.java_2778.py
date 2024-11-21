Here is the translation of the given Java code into Python:

```Python
class NotInRangeColumnConstraint:
    def __init__(self, name="Not In Range", min_value=None, max_value=None):
        self.name = name
        self.min_value = min_value
        self.max_value = max_value

    @property
    def accepts(self, value, context):
        if value is None:
            return False
        return value < self.min_value or value > self.max_value

    def copy(self, min_value=None, max_value=None):
        return NotInRangeColumnConstraint(name=self.name, min_value=min_value, max_value=max_value)

# Example usage:

not_in_range = NotInRangeColumnConstraint(min_value=1, max_value=10)
print(not_in_range.accepts(5))  # True
print(not_in_range.accepts(-2))  # False
print(not_in_range.copy().accepts(15))  # False

```

Please note that Python does not support generics like Java. Therefore, the `T` type parameter in the original code has been removed and replaced with a simple class attribute for storing the minimum and maximum values.