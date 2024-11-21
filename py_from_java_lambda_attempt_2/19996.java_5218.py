Here is the translation of the Java code to Python:
```python
class StoppableIterator:
    def __init__(self, iter, stopper, return_last):
        self.iter = iter
        self.stopper = stopper
        self.return_last = return_last
        if not return_last and iter.has_next():
            self.current = next(iter)

    def has_next(self):
        cn = self.called_next
        self.called_next = False
        if self.stopped or not self.iter.has_next():
            return False
        if cn and not self.return_last:
            self.current = next(self.iter)
            if self.stopper.check(self.current):
                self.stop()
                return False
        return True

    def __next__(self):
        if not self.has_next():
            raise StopIteration
        self.called_next = True
        if not self.return_last:
            return self.current
        t = next(self.iter)
        if self.stopper.check(t):
            self.stop()
        return t

    def remove(self):
        self.iter.remove()

    def stop(self):
        self.stopped = True


class NullableChecker:
    def __init__(self, func):
        self.func = func

    def check(self, x):
        return self.func(x)
```
Note that I had to create a separate `NullableChecker` class in Python, as there is no direct equivalent of Java's `@Nullable` annotation. In this implementation, the `check` method simply calls the provided function with the given argument.

Also, I used the built-in `StopIteration` exception instead of manually throwing a `NoSuchElementException`.