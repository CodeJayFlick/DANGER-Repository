Here is the translation of the given Java interface into a Python class:

```Python
class CompositeChangeListener:
    def __init__(self):
        pass

    def component_changed(self, ordinal: int) -> None:
        """
        Indicates the ordinal of the component which has been added, updated or cleared.
        
        :param ordinal: Component ordinal
        """
        # Your code here
```

Note that Python does not have a direct equivalent to Java's interface. Instead, we can use abstract base classes (ABCs) from the `abc` module in Python. However, since you didn't ask for an ABC and just wanted a translation of the given Java interface into Python, I provided a simple class with a method that matches the signature of the original Java method.