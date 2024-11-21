Here is the translation of the Java interface `DBRecordAdapter` to a Python class:

```python
import io

class DBRecordAdapter:
    def get_records(self, start: int, end: int, col_index: int) -> object:
        # Implement your logic here to return a record iterator.
        pass  # Replace with actual implementation.

# Example usage:
adapter = DBRecordAdapter()
records = adapter.get_records(0, 100, 1)
```

Note that in Python, we don't have an equivalent concept of interfaces like Java. Instead, we use abstract base classes (ABCs) or protocols to define a set of methods that must be implemented by any class that inherits from it.

In this example, I've defined a simple `DBRecordAdapter` class with a single method `get_records`, which takes three integer arguments and returns an object representing the record iterator. The implementation is left blank for you to fill in according to your specific requirements.