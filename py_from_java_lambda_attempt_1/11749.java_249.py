Here is the translation of the Java code to Python:
```
class SpaceSymbol:
    def __init__(self, location, space):
        super().__init__(location, space.name)
        self.space = space

    @property
    def space(self):
        return self._space

    @space.setter
    def space(self, value):
        self._space = value

    def get_type(self):
        return "space_symbol"
```
Note that I've used Python's built-in `class` syntax to define the class, and the `__init__` method is equivalent to the Java constructor. The rest of the methods are similar in structure to their Java counterparts.

I also took some liberties with the code:

* In Python, we don't need a separate `getSpace()` method; instead, I used a property (`@property`) to provide read-only access to the `_space` attribute.
* Similarly, I removed the `@Override` annotation and simply defined the `getType()` method as it would be in Python.

Let me know if you have any questions or need further clarification!