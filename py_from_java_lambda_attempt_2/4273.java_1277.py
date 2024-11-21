Here is the translation of the Java code to Python:
```
class DataSearchAddressIterator:
    def __init__(self, data_iterator: Iterator[Data], forward: bool):
        self.data_iterator = data_iterator
        self.forward = forward
        self.current_data = None
        self.current_iter = None

    def has_next(self) -> bool:
        if self.current_iter is not None and self.current_iter.has_next():
            return True
        return self.data_iterator.hasNext()

    def next(self) -> Address:
        if self.current_iter is not None and self.current_iter.has_next():
            return self.current_iter.next()
        current_data = self.data_iterator.next()
        addresses = set(range(current_data.get_min_address(), current_data.get_max_address() + 1))
        self.current_iter = iter(addresses)
        return next(self.current_iter)

    def remove(self) -> None:
        raise NotImplementedError

    def __iter__(self):
        return self
```
Note that I've used the following Python features:

* `__init__` method to initialize the object's state
* Type hints for function parameters and variables (e.g. `Iterator[Data]`)
* List comprehensions are not needed in this case, as we're working with iterators instead of lists.
* The `set` data structure is used to represent a set of addresses, which can be iterated over using the `iter` function.

Also note that I've kept the same method names and variable names as the original Java code, but adapted them to Python's syntax.