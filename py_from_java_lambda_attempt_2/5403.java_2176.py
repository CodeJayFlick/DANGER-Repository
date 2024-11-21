Here is the translation of the Java code to Python:
```
class LoaderOpinionException(Exception):
    def __init__(self):
        super().__init__()

    def __init__(self, message: str, cause=None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        else:
            super().__init__(message)

    def __init__(self, message: str) -> None:
        super().__init__(message)

    def __init__(self, cause: Exception) -> None:
        super().__init__(cause)
```
Note that in Python, we don't need to specify the type of a variable or method parameter unless it's necessary for clarity. Also, the `extends` keyword is not used in Python; instead, we define classes using the `class` statement and inherit from other classes by calling their constructors with `super()`.