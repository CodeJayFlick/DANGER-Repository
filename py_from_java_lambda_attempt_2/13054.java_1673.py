Here is the translation of the Java interface `Issue` into a Python class:

```python
class Issue:
    def __init__(self):
        pass

    @property
    def category(self):
        """Returns the category for this issue."""
        raise NotImplementedError("category must be implemented")

    @property
    def description(self):
        """Returns a detailed description of the issue."""
        raise NotImplementedError("description must be implemented")

    @property
    def primary_location(self):
        """Returns a Location object that describes where the issue occurred. May return None if the issue is not related to a specific location."""
        raise NotImplementedError("primary_location must be implemented")

    @property
    def secondary_locations(self):
        """Returns a list of locations related to the issue that are not the primary issue location. This list may be empty, but not null."""
        raise NotImplementedError("secondary_locations must be implemented")

    @property
    def possible_fixups(self):
        """Returns a list of possible Fixup objects for this issue. This list may be empty, but not null."""
        raise NotImplementedError("possible_fixups must be implemented")
```

Note that I used Python's `@property` decorator to create read-only properties from the Java interface methods. In Python, you don't need to explicitly define getter and setter methods like in Java; instead, you can use the `@property` decorator to make a method readable or writable.

Also, since this is an abstract class (similar to an interface in Java), I didn't provide any implementation for these properties. Instead, each property raises a `NotImplementedError`, indicating that subclasses must implement them.