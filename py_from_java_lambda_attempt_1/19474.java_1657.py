Here is the translation of the given Java code into Python:

```Python
class ArithmeticGettable:
    def __call__(self, event: object, as_integer: bool) -> float:
        pass  # This method should be implemented in a subclass.
```

Note that this is an interface (or abstract class) in Java and can't be directly translated to Python. In Python, we use classes or functions instead of interfaces. The `__call__` method is used here because it's the closest equivalent to the `get` method in Java which takes two parameters.

Here's a more concrete example with an implementation:

```Python
class ArithmeticGettable:
    def __init__(self):
        pass

    def get(self, event: object, as_integer: bool) -> float:
        if isinstance(event, int):  # Assuming 'event' is supposed to be some kind of number.
            return event if not as_integer else round(event)
        raise ValueError("Event must be a number.")
```

This implementation assumes that the `get` method should work with integers and floats.