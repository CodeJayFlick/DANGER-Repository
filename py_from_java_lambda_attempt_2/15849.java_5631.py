Here is the translation of the Java interface `ThrowingFunction` into a Python class:

```python
class ThrowingFunction:
    def __init__(self):
        pass

    def apply(self, t) -> object:
        raise NotImplementedError("This function must be implemented")
```

Note that in Python, we don't have an equivalent to the Java concept of interfaces. Instead, we use abstract base classes (ABCs), which are defined using the `abc` module and the `@abstractmethod` decorator.

However, since you specifically asked for a translation into Python only, I've implemented this as a regular class with a method that raises a `NotImplementedError`. This is not equivalent to the Java interface's functional interface concept, but it serves as a rough approximation.