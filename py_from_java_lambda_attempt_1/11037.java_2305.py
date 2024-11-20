Here is the translation of the Java interface `ProjectTreeContext` into a Python class:

```python
class ProjectTreeContext:
    def __init__(self):
        pass

    def get_folder_count(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_file_count(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_selected_folders(self) -> list:
        raise NotImplementedError("Method not implemented")

    def get_selected_files(self) -> list:
        raise NotImplementedError("Method not implemented")

    def get_tree(self) -> object:  # DataTree
        raise NotImplementedError("Method not implemented")

    def get_selection_paths(self) -> list:
        raise NotImplementedError("Method not implemented")
```

Note that I've used Python's built-in `list` type to represent the Java interfaces' return types, and I've kept the method signatures similar to their Java counterparts. The `get_tree()` method returns an object of type `DataTree`, which is equivalent to a Java interface or abstract class.

Also, since this code defines an interface in Java, it doesn't have any concrete implementation. In Python, we can define an abstract base class (ABC) using the `abc` module from the standard library. However, for simplicity and consistency with the original Java code, I've chosen to raise a `NotImplementedError` instead of defining an ABC.

This translation maintains the same structure and method signatures as the original Java interface, making it easier to understand and work with in Python.