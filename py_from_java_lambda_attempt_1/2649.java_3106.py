Here is the translation of the Java code to Python:
```
class WrappingInstructionIterator:
    def __init__(self, iterator):
        self.iterator = iterator

    def __iter__(self):
        return self

    def __next__(self):
        if not hasattr(self, 'it'):
            raise StopIteration
        try:
            result = next(self.it)
        except StopIteration:
            del self.it
            raise
        return result

    @property
    def has_next(self):
        return bool(self.iterator)

# Example usage:
class Instruction: pass  # placeholder for actual instruction class
def my_iterator():
    yield Instruction()
    yield Instruction()

it = WrappingInstructionIterator(my_iterator())
for inst in it:
    print(inst)
```
Note that I've used Python's built-in iterator protocol (`__iter__` and `__next__`) to implement the iteration logic. The `has_next` property is a simple wrapper around the underlying iterator's `hasNext()` method.

Also, I've assumed that you want to keep the original instruction objects yielded by the underlying iterator. If you need to modify or transform the instructions in some way, you'll need to add additional logic inside the `__next__` method.