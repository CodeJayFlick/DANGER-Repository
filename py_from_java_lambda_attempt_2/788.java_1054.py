Here is the translation of the Java interface into a Python class:

```Python
class DbgModelTargetSymbolContainer:
    def __init__(self):
        pass

    def get_target_symbol(self, symbol: 'DbgMinimalSymbol') -> 'DbgModelTargetSymbolImpl':
        # This method should be implemented in the subclass.
        raise NotImplementedError("Method not implemented")
```

Note that Python does not have a direct equivalent to Java's interface. Instead, we can use abstract base classes (ABCs) or protocols from third-party libraries like `typing` and `abc`. However, since you only asked for a translation into pure Python, I've used the simplest approach: creating an ordinary class with an unimplemented method that raises a `NotImplementedError`.

The type hints are included to provide information about the expected types of arguments and return values.