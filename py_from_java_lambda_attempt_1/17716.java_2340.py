Here is the translation of the Java interface `ILogReader` to a Python class:

```python
import io

class ILogReader:
    def __init__(self):
        pass

    def close(self) -> None:
        """Release resources occupied by this object."""
        raise NotImplementedError("Subclasses must implement this method")

    def hasNext(self) -> bool:
        """Return whether there exists next log to be read."""
        raise FileNotFoundError("No more logs available")
        # return False  # or True, depending on your implementation

    def next(self) -> io.IOError:
        """Return the next log as a PhysicalPlan"""
        raise NoSuchElementException("There are no more logs") from FileNotFoundError
        # return None  # or some other value, depending on your implementation


class NoSuchElementException(Exception):
    pass
```

Note that I've used Python's built-in `io` module to represent exceptions similar to Java's `IOException`. The `close`, `hasNext`, and `next` methods are implemented as abstract methods in the interface, which means they must be implemented by any subclass.