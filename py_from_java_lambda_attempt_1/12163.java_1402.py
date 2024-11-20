Here is the translation of the Java code into Python:

```Python
class GenericAddressSpace:
    def __init__(self, name: str, size: int, unit_size: int = 1, type: int = None, unique_id: int = None):
        pass

    def get_address(self, offset: int) -> 'GenericAddress':
        return GenericAddress(self, offset)

    def get_address_in_this_space_only(self, offset: int) -> 'GenericAddress':
        return self.get_address(offset)

    @property
    def show_space_name(self) -> bool:
        pass

    def set_show_space_name(self, value: bool):
        pass


class GenericAddress:
    def __init__(self, address_space: 'GenericAddressSpace', offset: int):
        self.address_space = address_space
        self.offset = offset
```

Please note that this is a direct translation of the Java code into Python. However, there are some differences between the two languages:

1. Inheritance: Python does not support inheritance in the same way as Java. Instead, you can use composition to achieve similar results.

2. Method overriding: Python supports method overriding through the use of `super()` function and by defining a new method with the same name but different parameters (if any).

3. Static methods: Python does not have static methods like Java. You can define class-level functions or instance-level methods that do not require an object to be called.

4. Access modifiers: Python does not support access modifiers like public, private etc., unlike Java. However, you can achieve similar results by using underscore prefix for variables and methods which are intended to be private.

5. Exception handling: Python has a different way of exception handling compared to Java. You can use `try-except` block or raise exceptions manually.

6. Type hinting: Python supports type hinting through the use of colon (:) followed by the expected data type, unlike Java which uses keyword like int for primitive types and class name for objects.