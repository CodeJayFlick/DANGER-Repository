Here is the equivalent Python code:

```Python
class ListAccumulator:
    def __init__(self):
        self.list = []

    def add(self, t):
        self.list.append(t)

    def add_all(self, collection):
        for item in collection:
            self.add(item)

    def contains(self, t):
        return t in self.list

    def get(self):
        return self.list.copy()

    def as_list(self):
        return self.list

    def size(self):
        return len(self.list)

    def __iter__(self):
        return iter(self.list)

    def __str__(self):
        return str(self.list)
```

Note that Python does not have a direct equivalent to Java's generics, so the `T` type parameter is omitted. Also, Python's list class has an `append` method for adding elements and an `in` operator for checking if an element exists in the list. The `get` method returns a copy of the internal list because lists are mutable in Python and returning the original list could lead to unexpected behavior.