Here is the translation of the given Java code into equivalent Python:

```Python
class OptionsVetoException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
```

Note that in Python, we don't need to specify a return type for methods (like `public` or `def`) as it is inferred by the interpreter. Also, exception handling and raising are similar but not identical between Java and Python.