Here is the translation of the given Java code into Python:

```Python
class Soldier:
    def __init__(self, *children):
        super().__init__(*children)

    def accept(self, visitor):
        visitor.visit_soldier(self)
        super().accept(visitor)

    def __str__(self):
        return "soldier"
```

Note that in the `__init__` method, I used Python's unpacking feature (`*`) to pass all children as arguments to the superclass constructor.