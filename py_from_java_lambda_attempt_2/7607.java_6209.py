Here is the translation of the Java interface `FidHashQuad` into a Python class:

```python
class FidHashQuad:
    def __init__(self):
        pass

    @property
    def code_unit_size(self):
        """Returns the actual number of code units used to compute the full hash value."""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def full_hash(self):
        """Returns the full hash value."""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def specific_hash_additional_size(self):
        """Returns the ADDITIONAL number of code units, past the number used for the full hash,
           used to compute the specific hash value."""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def specific_hash(self):
        """Returns the specific hash value."""
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I've implemented these as properties, which are a way of exposing instance variables in Python. The `@property` decorator allows you to define getter methods for these properties.

In Java, interfaces can only contain abstract methods (i.e., methods without an implementation), whereas classes can have both concrete and abstract methods. In Python, we don't have direct equivalents to Java's interface or class concepts; instead, we use inheritance and polymorphism to achieve similar effects.