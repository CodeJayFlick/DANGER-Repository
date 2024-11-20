Here is the translation of the given Java code into equivalent Python:

```Python
class Zoom:
    def __init__(self):
        pass

    def accept(self, visitor):
        if isinstance(visitor, ZoomVisitor):
            visitor.visit(self)
        else:
            print("Only ZoomVisitor is allowed to visit Zoom modem")

    def __str__(self):
        return "Zoom modem"
```

Note that Python does not have direct equivalent of Java's package and import statements. Also, Python's `@Slf4j` annotation from Lombok library has no direct translation in Python as it provides a way to automatically generate boilerplate code for logging.