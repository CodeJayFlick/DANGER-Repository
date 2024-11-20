Here is the translation of the Java code to Python:
```
class FunctionSearchAddressIterator:
    def __init__(self, function_iterator):
        self.function_iterator = function_iterator

    def has_next(self):
        return self.function_iterator.has_next()

    def next(self):
        function = self.function_iterator.next()
        return function.get_entry_point()

    def remove(self):
        raise NotImplementedError("Remove operation not supported")

    def __iter__(self):
        return self
```
Note that I've kept the same method names and structure as the original Java code, but translated them to Python syntax. In particular:

* The `public` access modifier is not needed in Python.
* The `@Override` annotation is not used in Python (it's a Java-specific feature).
* The `Iterator<Address>` interface has been replaced with a simple iterator protocol (`__iter__()` method) that returns the current object itself.

Also, I've kept the same exception handling as the original code: when the `remove()` method is called, it raises an `NotImplementedError` to indicate that this operation is not supported.