Here is the translation of the Java interface `ProgramDropProvider` into a Python class:

```python
class ProgramDropProvider:
    def __init__(self):
        pass

    def get_priority(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_data_flavors(self) -> list[DataFlavor]:
        raise NotImplementedError("Method not implemented")

    def is_drop_ok(self, context_obj: object, evt: DropTargetDragEvent) -> bool:
        raise NotImplementedError("Method not implemented")

    def add(self, context_obj: object, data: object, flavor: DataFlavor):
        raise NotImplementedError("Method not implemented")


class DataFlavor:
    pass


class DropTargetDragEvent:
    pass
```

Note that I had to create placeholder classes for `DataFlavor` and `DropTargetDragEvent`, as these are Java-specific classes that don't have direct equivalents in Python.