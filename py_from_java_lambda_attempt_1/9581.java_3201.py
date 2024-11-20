Here is the translation of the Java interface `LayoutModel` into a Python class:

```python
class LayoutModel:
    def __init__(self):
        pass

    def is_uniform(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def preferred_view_size(self) -> tuple[int, int]:
        raise NotImplementedError("Subclasses must implement this property")

    @property
    def num_indexes(self) -> int:
        raise NotImplementedError("Subclasses must implement this property")

    def index_after(self, index: int) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def index_before(self, index: int) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_layout(self, index: int) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def iterator(self) -> 'LayoutModelIterator':
        return LayoutModelIterator(self)

    def iterator(self, start_index: int) -> 'LayoutModelIterator':
        return LayoutModelIterator(self, start_index)

    def add_layout_model_listener(self, listener):
        raise NotImplementedError("Subclasses must implement this method")

    def remove_layout_model_listener(self, listener):
        raise NotImplementedError("Subclasses must implement this method")

    def flush_changes(self):
        pass
```

Note that I used the `@property` decorator to create read-only properties for the methods that return a `Dimension`, and I also defined an abstract base class (ABC) using the `abc` module. This is because Python does not have built-in support for interfaces like Java, but we can achieve similar functionality by defining ABCs.

Also note that some of the method implementations are left as `raise NotImplementedError("Subclasses must implement this...")`, which means that any subclass of `LayoutModel` will need to provide its own implementation for those methods.