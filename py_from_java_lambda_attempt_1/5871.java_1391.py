Here is the equivalent Python code for the given Java class:

```Python
class MemSearchResult:
    def __init__(self, address: 'Address', length: int):
        if not isinstance(address, Address) or length <= 0:
            raise ValueError("Invalid input")
        self.address = address
        self.length = length

    @property
    def get_address(self):
        return self.address

    @property
    def get_length(self):
        return self.length

    def __eq__(self, other: 'MemSearchResult'):
        if not isinstance(other, MemSearchResult):
            return False
        return self.address == other.address

    def __lt__(self, other: 'MemSearchResult'):
        return self.address < other.address

    def __hash__(self):
        return hash((self.address,))

    def __str__(self):
        return str(self.address)

class Address:
    pass  # You would need to implement the Address class in Python
```

Note that I've used type hints for the `__init__` method and the `addressEquals` method. This is not necessary if you're using a static analyzer or linter, but it can be helpful for code readability.

Also note that I haven't implemented the `Address` class because Java's `Address` class seems to have been left out of this translation. You would need to implement your own equivalent in Python.