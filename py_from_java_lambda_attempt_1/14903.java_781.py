Here is the translation of the Java code to Python:
```
class BaseEntity:
    def __init__(self):
        pass

    @property
    def id(self) -> int | None:
        raise NotImplementedError("Subclasses must implement getId()")

    @id.setter
    def id(self, value: int | None) -> None:
        self._id = value

    @property
    def name(self) -> str:
        raise NotImplementedError("Subclasses must implement getName()")

    @name.setter
    def name(self, value: str) -> None:
        self._name = value

    def __str__(self):
        return f"BaseEntity(id={self.id}, name='{self.name}')"
```
Note that I've used Python's built-in `property` decorator to implement getter and setter methods for the `id` and `name` attributes. This is equivalent to Java's abstract methods, but with a more Pythonic syntax.

Also, since this is an abstract class in Java, there is no direct equivalent in Python (since Python doesn't have abstract classes). Instead, I've implemented the properties as abstract by raising a `NotImplementedError` when they are accessed. This allows subclasses to implement their own versions of these methods while still providing some basic functionality.

Finally, I added an `__str__` method to provide a string representation of the object, which is equivalent to Java's `toString()` method.