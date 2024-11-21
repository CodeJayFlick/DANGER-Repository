Here is the translation of the Java code to Python:
```
class ArrayIterator:
    def __init__(self, array: list | None = None, start: int = 0) -> None:
        self.array = array
        self.index = start

    def hasNext(self) -> bool:
        if not self.array:
            return False
        return self.index < len(self.array)

    def next(self) -> object | None:
        if not self.array or self.index >= len(self.array):
            raise StopIteration
        result = self.array[self.index]
        self.index += 1
        return result

    def remove(self) -> None:
        raise NotImplementedError("remove is not supported for arrays")
```
Note that I used the `list | None` type hint to indicate that the `array` parameter can be either a list or `None`. This is equivalent to Java's `@Nullable T[] array;`.

I also replaced the `NoSuchElementException` with Python's built-in `StopIteration`, which is raised when there are no more elements in an iterator.

Finally, I used the `NotImplementedError` exception to indicate that the `remove()` method is not supported for arrays.