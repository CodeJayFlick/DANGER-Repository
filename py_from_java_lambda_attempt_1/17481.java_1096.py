Here's a translation of the Java interface into equivalent Python code:

```Python
class ManagedSeriesReader:
    def is_managed_by_query_manager(self) -> bool:
        pass  # To be implemented by subclasses

    def set_managed_by_query_manager(self, managed_by_query_manager: bool):
        pass  # To be implemented by subclasses

    def has_remaining(self) -> bool:
        pass  # To be implemented by subclasses

    def set_has_remaining(self, has_remaining: bool):
        pass  # To be implemented by subclasses
```

This Python code defines a class `ManagedSeriesReader` with the same methods as the Java interface. The method bodies are left empty (`pass`) because they need to be implemented in any subclass that inherits from this one.

Note that there is no direct equivalent of Java's `extends IBatchReader` syntax, which indicates inheritance and type constraints. In Python, you would typically define a class with methods that match the interface or abstract base class (ABC) being extended.