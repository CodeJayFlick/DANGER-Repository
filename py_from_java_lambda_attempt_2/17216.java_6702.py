Here is the translation of the given Java code into equivalent Python:

```Python
class FillClauseComponent:
    def __init__(self):
        self.fill_types = {}

    @property
    def fill_types(self):
        return self._fill_types

    @fill_types.setter
    def fill_types(self, value):
        self._fill_types = value


# Note: Python does not have direct equivalent of Java's package declaration.
```

Here are the key differences between the two languages:

1. **Class Declaration**: In Java, classes are declared with `public class`, while in Python, they're simply defined using the `class` keyword.

2. **Method Definition**: In Java, methods are declared inside a class and have access modifiers (like public or private). In Python, methods are also defined within a class but don't require explicit declaration of their return types or access levels.

3. **Property Getter and Setter**: The equivalent of Java's getter and setter methods in Python is achieved using the `@property` decorator for read-only properties and by defining a separate method with an underscore prefix (like `_fill_types`) to make it private, which can then be accessed through the property name (`self.fill_types`).