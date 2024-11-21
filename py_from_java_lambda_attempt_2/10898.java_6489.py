Here is the translation of the given Java code into Python:

```Python
class TestEdge:
    def __init__(self, start: 'AbstractTestVertex', end: 'AbstractTestVertex'):
        super().__init__(start, end)

    def clone_edge(self) -> 'TestEdge':
        return self.__class__(self.start, self.end)
```

Note that Python does not have direct equivalent of Java's package declaration. Also, the `@Override` annotation is not necessary in Python as it doesn't support method overriding like Java does.

The `AbstractVisualEdge` and `AbstractTestVertex` classes are also not defined here as they seem to be custom classes specific to your project. In a real-world scenario, you would need to define these classes or import them from some other module if they already exist in your codebase.