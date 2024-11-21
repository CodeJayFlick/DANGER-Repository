Here is the translation of the Java code to Python:
```
class DisjunctionSelector:
    def __init__(self, *selectors):
        self.leaf_components = list(selectors)

    def test(self, t):
        return any(comp.test(t) for comp in self.leaf_components)
```
Note that I've removed the type parameter `<T>` since Python is dynamically typed and doesn't require explicit type declarations.

Also, I replaced `@SafeVarargs` with nothing, as it's not a meaningful concept in Python (varargs are handled automatically).

The rest of the code remains similar: we create an instance variable `leaf_components` to store the list of leaf selectors, and define a method `test` that returns `True` if at least one of the leaf components passes the test.