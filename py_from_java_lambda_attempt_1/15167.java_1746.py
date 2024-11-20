Here is the translation of the Java code to Python:
```
class Commander:
    def __init__(self, *children):
        super().__init__(*children)

    def accept(self, visitor):
        visitor.visit_commander(self)
        super().accept(visitor)

    def __str__(self):
        return "commander"
```
Note that I've used the `super()` function to call the parent class's constructor and methods. In Python, this is equivalent to calling the superclass's method using the dot notation (e.g., `Unit.__init__`).

Also, in Python, we don't need explicit getters or setters for attributes, so I didn't include any of those.

Finally, the `toString()` method has been replaced with a simple `__str__` method, which is called when you try to convert an object to a string using the `str()` function.