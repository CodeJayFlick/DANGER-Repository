Here is the translation of the Java code to Python:
```
class Node:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_type(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that I've used Python's `raise` statement to indicate that the methods are abstract and should be implemented by subclasses.