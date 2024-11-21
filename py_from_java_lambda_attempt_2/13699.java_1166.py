Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright © 2014-2021 Ilkka Seppälä

class KingdomFactory:
    """Kingdom factory interface."""

    def create_castle(self):
        pass

    def create_king(self):
        pass

    def create_army(self):
        pass


if __name__ == "__main__":
    # You can use this class to implement the actual kingdom factories
    pass
```

Please note that in Python, we don't have a direct equivalent of Java's interface. Instead, we define classes with abstract methods (methods without implementation) using the `abc` module from the standard library or by conventionally prefixing method names with an underscore.