Here is the equivalent Python code:

```Python
class AbstractUnionedCollection:
    def __init__(self, collections):
        self.collections = collections

    @staticmethod
    def from_varargs(*collections):
        return AbstractUnionedCollection(list(collections))

    def size(self):
        total_size = 0
        for col in self.collections:
            total_size += len(col)
        return total_size

    def is_empty(self):
        for col in self.collections:
            if not col:
                return False
        return True

    def contains(self, o):
        for col in self.collections:
            if o in col:
                return True
        return False

    def remove(self, o):
        removed = False
        for col in self.collections:
            if col.remove(o):
                removed = True
        return removed

    def remove_all(self, c):
        result = False
        for col in self.collections:
            result |= col.difference(c)
        return result

    def retain_all(self, c):
        result = False
        for col in self.collections:
            result |= col.intersection(c)
        return result

    def clear(self):
        for col in self.collections:
            col.clear()
```

Note that Python does not have direct equivalents to Java's `@SafeVarargs` or the `AbstractCollection` class. The equivalent of these is simply using a list comprehension and defining your own methods as needed.