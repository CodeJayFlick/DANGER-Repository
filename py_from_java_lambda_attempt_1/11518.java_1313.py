Here is the translation of the given Java code into Python:

```Python
class SleighException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, e):
        super().__init__(message, e)
```

Note that in Python, we don't need to specify the `public` access modifier as it is not applicable. Also, Python's exception handling mechanism does not require a separate class for exceptions like Java does.