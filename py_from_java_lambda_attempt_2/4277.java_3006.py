Here is the translation of the given Java code into Python:

```Python
class SearchAddressIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> 'Address':
        raise NotImplementedError("Subclasses must implement this method")


class Address:
    def __init__(self, value: str):
        self.value = value
```

Note that in Python, we don't have a direct equivalent of Java's `interface`. Instead, we use abstract base classes (ABCs) to define interfaces. In the above code, I've defined an ABC called `SearchAddressIterator` with two methods: `has_next()` and `next()`. These are meant to be implemented by any subclass that wants to conform to this interface.

I have also defined a simple class `Address` which has one attribute `value`, but you can add more attributes or functionality as needed.