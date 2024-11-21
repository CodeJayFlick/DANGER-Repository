Here is the translation of the given Java interface into a Python class:

```Python
class UnitVisitor:
    def visit_soldier(self, soldier):
        pass  # Implement this method in your subclass

    def visit_serjeant(self, serjeant):
        pass  # Implement this method in your subclass

    def visit_commander(self, commander):
        pass  # Implement this method in your subclass
```

Note that Python does not have a direct equivalent to Java's interface. Instead, we can use abstract base classes (ABCs) or protocols from the `typing` module. However, since you asked for only Python code and did not specify any particular approach, I provided an implementation using regular classes with abstract methods.