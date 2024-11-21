Here is the translation of the Java code to Python:
```
class ElfWeapon:
    def __init__(self, weapon_type: str):
        self.weapon_type = weapon_type

    @property
    def weapon_type(self) -> str:
        return self._weapon_type

    def __str__(self) -> str:
        return f"an elven {self.weapon_type}"
```
Note that I've used Python's built-in `__init__` method to initialize the object, and a property (`@property`) to expose the `weapon_type` attribute. The `__str__` method is equivalent to Java's `toString()` method.

Also, since there is no direct equivalent of Java's `lombok` library in Python, I've used Python's built-in syntax for defining properties and methods.