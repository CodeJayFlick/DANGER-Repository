Here is the translation of the Java code to Python:
```
import itertools

class FilteredIterator:
    def __init__(self, it: iter, filter_func):
        self.it = it
        self.filter_func = filter_func
        self.next_thing = None

    def hasNext(self) -> bool:
        if self.next_thing is not None:
            return True
        return self.find_next()

    def next(self) -> object:
        if self.hasNext():
            thing = self.next_thing
            self.next_thing = None
            return thing
        return None

    def find_next(self):
        for item in self.it:
            if self.filter_func(item):
                self.next_thing = item
                return True
        return False

    def remove(self) -> None:
        raise NotImplementedError("remove is not implemented")

    def __iter__(self):
        return self


# Example usage:
def my_filter(x: int) -> bool:
    return x % 2 == 0

it = iter([1, 2, 3, 4, 5])
filtered_it = FilteredIterator(it, my_filter)

for item in filtered_it:
    print(item)
```
Note that I used the `itertools` module to get an iterator object (`iter`) and also defined a simple filter function `my_filter`. You can replace this with your own filtering logic.