Here is the translation of the Java code to Python:

```
class IncompatibleLanguageException(Exception):
    """ Exception thrown when attempting to replace one language in a program with another that 
       is not "address space" compatable.
    """

    def __init__(self, msg: str) -> None:
        super().__init__(msg)
```