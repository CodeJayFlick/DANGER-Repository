Here is the translation of the Java interface `ZooProvider` into a Python class:

```python
class ZooProvider:
    def __init__(self):
        pass

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def get_model_zoo(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I've used Python's built-in `@property` decorator to create a read-only property for the `name`, which is equivalent to Java's getter method. The `get_model_zoo` method has been translated into a regular instance method, and its return type annotated with `-> object`.