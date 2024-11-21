Here's the equivalent Python code:

```Python
class MNodeTypeMismatchException(Exception):
    def __init__(self, path: str, expected_type: int) -> None:
        super().__init__(
            f"MNode [{path}] is not a {MetadataConstant.get_m_node_type_name(expected_type)}"
        )
```

Note that I've used Python's built-in `Exception` class as the base class for our custom exception. The constructor (`__init__`) takes two arguments: `path` and `expected_type`. We use string formatting to create an error message, which is then passed to the parent class using the `super().__init__(message)` call.

Also note that I've assumed there's a separate module or class called `MetadataConstant` with a method `get_m_node_type_name(expected_type)`, as it seems you're trying to translate Java code and this would be equivalent in Python.