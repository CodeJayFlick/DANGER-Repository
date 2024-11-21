Here is the translation of the Java code to Python:
```
class IllegalPanelStateException(Exception):
    """Allows unexpected IOExceptions and other errors to be thrown during Wizard panel transitions"""
    def __init__(self, cause: Exception) -> None:
        super().__init__(cause)
```
Note that in Python, we don't need a `public` keyword for classes or methods. Also, the constructor is simply called `__init__`, and it takes an optional argument `cause`. The rest of the code remains similar to the Java original.