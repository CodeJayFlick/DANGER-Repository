Here is the translation of the Java interface `AddressChangeSet` into a Python class:

```python
class AddressChangeSet:
    def __init__(self):
        self.address_set = set()

    def get_address_set(self) -> 'set[Address]':
        return self.address_set

    def add(self, addr_set: 'set[Address]'):
        self.address_set.update(addr_set)

    def add_range(self, start_addr: Address, end_addr: Address):
        for addr in range(start_addr, end_addr + 1):
            self.add({addr})
```

Note that I've made the following changes:

* In Python, we don't need to declare types or use `public` access modifiers. Instead, we define a class with an initializer (`__init__`) and methods.
* The Java interface's method return types are not explicitly declared in Python; instead, we rely on type hints (e.g., `-> 'set[Address]'`) for documentation purposes only.
* In the `add` method, I've used the `update` method to add all addresses from the input set (`addr_set`) to our internal address set. This is equivalent to Java's `addAll` method.
* The `add_range` method generates a range of addresses using Python's built-in `range` function and adds each individual address as a separate change.

Please note that this translation assumes you have an existing `Address` class in your Python code, which represents the same concept as the Java `Address` class.