Here is the translation of the Java code to Python:
```
class ReferenceIteratorTestStub:
    def __init__(self, refs):
        self.iterator = iter(refs)

    def remove(self):
        # do nothing for now
        pass

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self.iterator)
        except StopIteration:
            raise StopIteration()

    def has_next(self):
        try:
            next(self.iterator)
            return True
        except StopIteration:
            return False
```
Note that I've used Python's built-in `iter` function to create an iterator from the input collection, and implemented the `__next__` method using a generator expression. The `has_next` method is also simple to implement using the same approach.

Also, since there is no equivalent of Java's `Iterator.remove()` in Python, I've left it as a no-op for now. If you need to remove elements from the iterator, you would need to use a different data structure or algorithm that supports removals.