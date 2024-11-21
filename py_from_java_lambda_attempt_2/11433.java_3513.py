Here is the translation of the given Java code into Python:

```Python
class AssemblyTerminal:
    def __init__(self, name):
        self.name = name

    def match(self, buffer: str, pos: int, grammar, labels) -> list:
        pass  # abstract method implementation left to subclasses

    def get_suggestions(self, got: str, labels) -> list:
        pass  # abstract method implementation left to subclasses
```

Note that the `match` and `get_suggestions` methods are declared as abstract in Java because they are intended to be implemented by concrete subclasses. In Python, we can achieve a similar effect using abstract base classes (ABCs), but since ABCs were introduced in Python 3.4, I've chosen not to use them here for simplicity's sake.

Also note that the `Collection` and `Map` types from Java have been replaced with their equivalent data structures in Python: lists (`list`) and dictionaries (`dict`).