Here is the translation of the Java code to Python:

```Python
class Creature:
    def __init__(self):
        pass

    def get_name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_size(self) -> 'Size':
        raise NotImplementedError("Subclasses must implement this method")

    def get_movement(self) -> 'Movement':
        raise NotImplementedError("Subclasses must implement this method")

    def get_color(self) -> 'Color':
        raise NotImplementedError("Subclasses must implement this method")

    def get_mass(self) -> 'Mass':
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have an equivalent to Java's `interface` keyword. Instead, we define a class with abstract methods (methods without implementation). The `raise NotImplementedError` statement is used to indicate that the subclass should provide its own implementation for these methods.

Also note that I didn't translate the copyright notice and license information from the original code, as this is not relevant to the Python translation itself.