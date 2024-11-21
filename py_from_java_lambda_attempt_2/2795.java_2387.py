Here is the translation of the given Java code into Python:

```Python
class BackwardRecordIterator:
    def __init__(self, record_iterator):
        self.record_iterator = record_iterator

    def has_next(self):
        try:
            return self.record_iterator.has_previous()
        except Exception as e:
            print(f"An error occurred: {e}")
            return False

    def next(self):
        try:
            return self.record_iterator.previous()
        except Exception as e:
            print(f"An error occurred: {e}")
            raise StopIteration
```

Please note that Python does not have direct equivalents for Java's `IOException` and the concept of a checked exception. Instead, we can use Python's built-in exceptions (`Exception`) to handle any potential errors in our code.