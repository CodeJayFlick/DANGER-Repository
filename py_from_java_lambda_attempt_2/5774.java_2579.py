Here is the translation of the Java code to Python:
```python
class AddressRangeIteratorConverter:
    def __init__(self, iterator, program):
        self.iterator = iterator
        self.program = program
        self.next_range = None

    def __iter__(self):
        return self

    def remove(self):
        raise NotImplementedError("Cannot remove from this iterator")

    def has_next(self):
        if self.next_range is not None:
            return True
        while self.iterator.has_next():
            range_ = next(self.iterator)
            converted_range = DiffUtility.get_compatible_address_range(range_, self.program)
            if converted_range is not None:
                self.next_range = converted_range
                return True
        return False

    def __next__(self):
        if self.next_range is not None:
            result = self.next_range
            self.next_range = None
            return result
        if self.has_next():
            return self.next_range
        raise StopIteration()

class DiffUtility:
    @staticmethod
    def get_compatible_address_range(range_, program):
        # TODO: implement this method in Python equivalent to the Java code
        pass

# Example usage:
iterator = ...  # create an AddressRangeIterator instance
program = ...  # create a Program instance
converter = AddressRangeIteratorConverter(iterator, program)
for range_ in converter:
    print(range_)
```
Note that I've used Python's built-in `__iter__` and `__next__` methods to implement the iterator interface. The `remove` method is not implemented as it was throwing an exception in Java anyway.

Also, I've left the implementation of the `DiffUtility.get_compatible_address_range` method blank for now, assuming you'll fill that in with your own Python equivalent code.