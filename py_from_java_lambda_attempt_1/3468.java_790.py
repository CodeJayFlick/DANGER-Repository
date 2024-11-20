Here is the translation of the given Java code into equivalent Python:

```Python
class OutgoingFunctionCallNode:
    def __init__(self, program, function, source_address, filter_duplicates=False, filter_depth=0):
        super().__init__(program, function, source_address, 'FUNCTION_ICON', filter_duplicates, filter_depth)

    def recreate(self):
        return type(self)(self.program, self.function, self.source_address, self.filter_duplicates, self.filter_depth)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. Also, in Python, classes are defined using the `class` keyword and constructors (or initializer methods) are denoted by the `__init__` method. The equivalent of Java's `super()` call is achieved through the use of the `super()` function in Python.