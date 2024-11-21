Here is the translation of the given Java code into Python:

```Python
class Unit:
    def __init__(self, *children):
        self.children = list(children)

    def accept(self, visitor):
        for child in self.children:
            child.accept(visitor)
```

Note that this Python class does not include any type hints or docstrings.