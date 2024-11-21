Here is the equivalent Python code:

```Python
class DataRowObject:
    def __init__(self, key, address_map):
        self.key = key
        self.address_map = address_map

    @property
    def key(self):
        return self.key

    @property
    def address(self):
        return self.address_map.decode_address(self.key)

    def __hash__(self):
        prime = 31
        result = 1
        result = prime * result + (int((self.key ^ (self.key >> 32))))
        return result

    def __eq__(self, other):
        if self is other:
            return True
        if other is None:
            return False
        if not isinstance(other, DataRowObject):
            return False

        other_obj = other
        if self.key != other_obj.key:
            return False
        return True

    def __lt__(self, other):
        return (int(self.key)).__lt__((other).key)
```

Note that Python does not have a direct equivalent to Java's `Comparable` interface. The `compareTo` method in the original code is used for sorting and comparing objects of the same class. In Python, you can use the built-in comparison operators (`<`, `>`, etc.) or implement custom logic using methods like `__lt__`.