Here is the translation of the Java interface `IBatchReader` to a Python class:
```python
import io

class IBatchReader:
    def __init__(self):
        pass

    def has_next_batch(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next_batch(self) -> 'BatchData':
        raise NotImplementedError("Subclasses must implement this method")

    def close(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that I used the `NotImplementedError` exception to indicate that these methods are abstract and should be implemented by subclasses. This is similar to how Java interfaces work, where you can't instantiate an interface directly but rather create a class that implements it.

Also, in Python 3.x, the `-> bool`, `-> 'BatchData'`, and `-> None` syntax is used for type hints, which are not enforced at runtime.