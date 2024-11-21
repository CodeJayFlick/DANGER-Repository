Here's a translation of your Java code into equivalent Python:

```Python
class DBTraceProgramViewListing:
    def __init__(self, program):
        self.all_memory = set()
        super().__init__(program)

    def is_undefined(self, start: 'Address', end: 'Address') -> bool:
        for range in self.get_address_set(start, end):
            if not all(is_undefined_range(s, r) for s in self.program.viewport.get_ordered_snaps()):
                return False
        return True

    def clear_code_units(self, start_addr: 'Address', end_addr: 'Address', clear_context: bool, monitor=None):
        for range in self.get_address_set(start_addr, end_addr):
            if monitor and monitor.check_cancelled():
                break
            code_operations.defined_units().clear(range)

    def clear_all(self, clear_context: bool, monitor=None):
        try:
            for range in self.all_memory:
                code_operations.defined_units().clear(range)
        except CancelledException as e:
            raise AssertionError(e) from e

class AddressSet(set):
    pass
```

Note that I've used the following Python constructs:

- Classes: `DBTraceProgramViewListing` and `AddressSet`
- Inheritance: The `__init__` method of `DBTraceProgramViewListing` calls its parent class's constructor using `super().__init__(program)`
- Methods: Each Java method has been translated into a corresponding Python function
- Exception handling: I've used the standard Python exception handling syntax to translate your code.