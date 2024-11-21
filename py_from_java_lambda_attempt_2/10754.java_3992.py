Here's a translation of the Java interface into Python:

```Python
class GraphJob:
    def __init__(self):
        pass

    def execute(self, listener):
        # implement this method in your subclass
        raise NotImplementedError("execute must be implemented by subclasses")

    def can_shortcut(self) -> bool:
        # implement this method in your subclass
        raise NotImplementedError("can_shortcut must be implemented by subclasses")

    def shortcut(self):
        # implement this method in your subclass
        raise NotImplementedError("shortcut must be implemented by subclasses")

    @property
    def is_finished(self) -> bool:
        return False

    def dispose(self):
        pass


class GraphJobListener:
    pass  # define the interface for a listener, if needed
```

Note that Python does not have direct support for interfaces like Java. Instead, we use abstract base classes (ABCs) to provide a blueprint for subclasses. The `execute`, `can_shortcut`, and `shortcut` methods are declared as abstract using the `@property` decorator.

The `GraphJobListener` class is left undefined in this translation, but you would need to define it if you wanted to use listeners with your `GraphJob`.