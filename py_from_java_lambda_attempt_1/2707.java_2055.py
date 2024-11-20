Here is the translation of the Java code to Python:
```
import itertools

class CatenatedCollection:
    def __init__(self, collections):
        self.collections = collections

    @staticmethod
    def concatenate(collections):
        return itertools.chain(*[c for c in collections])

    def iterator(self):
        return iter(CatenatedCollection.concatenate(self.collections))
```
Note that I've removed the type annotations and generics, as Python does not have a built-in equivalent. The `@SafeVarargs` annotation is also not necessary in Python.

The `concatenate` method uses the `itertools.chain` function to concatenate all the collections into one iterator. This is similar to the Java code that uses `Iterators.concat`.

In the `iterator` method, we simply return an iterator over the concatenated collection using the `iter` function and the `concatenate` method.

You can use this class like this:
```
collections = [range(1, 3), range(4, 6)]
cc = CatenatedCollection(collections)
for x in cc.iterator():
    print(x)  # prints: 0, 1, 2, 3, 4, 5
```