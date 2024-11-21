Here is the translation of the given Java interface into a Python class:

```Python
class AbstractEmbedding:
    def __init__(self):
        pass

    def has_item(self, item):
        # This method should be implemented by subclasses.
        raise NotImplementedError("Subclasses must implement this method.")

    def embed(self, manager, items):
        # This method should be implemented by subclasses.
        raise NotImplementedError("Subclasses must implement this method.")
```

This Python class `AbstractEmbedding` is an abstract base class (ABC) that provides a blueprint for concrete embedding classes. The `has_item` and `embed` methods are declared as abstract, meaning they have to be implemented in any subclass of `AbstractEmbedding`.