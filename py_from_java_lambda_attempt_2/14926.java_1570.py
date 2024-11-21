Here is the translation of the Java interface into a Python class:

```Python
class Service:
    def __init__(self):
        pass

    @property
    def name(self):
        """The human readable name of the service"""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def id(self):
        """Unique ID of the particular service"""
        raise NotImplementedError("Subclasses must implement this method")

    def execute(self):
        """The workflow method that defines what this service does"""
        raise NotImplementedError("Subclasses must implement this method")
```

This Python class is similar to a Java interface. It has three properties: `name`, `id` and `execute`. The `@property` decorator makes these methods behave like getters, but they are actually abstract methods (like the ones in an interface) that need to be implemented by any subclass of this class.