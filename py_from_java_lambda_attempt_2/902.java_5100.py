Here is the translation of the given Java interface into a Python class:

```Python
class DataModelNameBinder:
    def bind_value(self, context_object: 'ModelObject', name: str) -> None:
        pass  # To be implemented by subclass or user

    def bind_reference(self, context_object: 'ModelObject', name: str) -> None:
        pass  # To be implemented by subclass or user

    def enumerate_values(self, context_object: 'ModelObject') -> 'KeyEnumerator':
        raise NotImplementedError("enumerate_values must be implemented")

    def enumerate_references(self, context_object: 'ModelObject') -> 'KeyEnumerator':
        raise NotImplementedError("enumerate_references must be implemented")
```

Please note that Python does not have direct equivalent of Java's interface. Instead, we can use abstract class or ABC (Abstract Base Class) to achieve similar functionality. However, in this case I've used a regular class with methods declared as `pass` which means they do nothing and are intended to be overridden by subclasses.

Also note that Python does not have direct equivalent of Java's `WString`. It is assumed here that you will use Python's built-in string type (`str`) instead.