Here is the translation of the Java code to Python:

```Python
class Hayes:
    def __init__(self):
        pass

    def accept(self, visitor):
        if isinstance(visitor, HayesVisitor):
            visitor.visit(self)
        else:
            print("Only HayesVisitor is allowed to visit Hayes modem")

    def __str__(self):
        return "Hayes modem"
```

Note that Python does not have a direct equivalent of Java's `@Slf4j` annotation. The logging functionality in the original code has been replaced with simple print statements for demonstration purposes only.

Also, note that there is no equivalent to Java's interface or abstract class concept in Python. Instead, you can use inheritance and polymorphism to achieve similar results.