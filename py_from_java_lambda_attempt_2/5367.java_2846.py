Here is the translation of the given Java code into equivalent Python:

```Python
class SingleLoaderFilter:
    def __init__(self, single: type, loader_args=None):
        self.single = single
        self.loader_args = loader_args if isinstance(loader_args, list) else None

    @property
    def loader_args(self):
        return self.loader_args

    def test(self, loader):
        return isinstance(loader.__class__, self.single)
```

Note that Python does not have direct equivalents for Java's `Class` and `List`, so we use the built-in types like `type` (for classes) and lists. The `@property` decorator is used to create a getter method for the `loader_args`.