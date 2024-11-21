Here's how you can translate this Java interface into a Python class:

```Python
class LldbModelTargetSymbol:
    def is_constant(self):
        # Your implementation here
        pass

    def get_value(self):
        # Your implementation here
        return None  # Replace with your actual value type

    def get_size(self):
        # Your implementation here
        return 0  # Replace with your actual size
```

Note that Python does not have a direct equivalent to Java's interface concept. Instead, you can use abstract base classes (ABCs) or interfaces implemented by other classes.

In this example, `LldbModelTargetSymbol` is just a regular class in Python and it doesn't enforce any contract on its subclasses like an interface would do in Java.