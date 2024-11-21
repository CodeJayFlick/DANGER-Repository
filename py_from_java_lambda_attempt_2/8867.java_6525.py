Here is the translation of the Java interface `VTRelatedMatch` to a Python class:

```python
class VTRelatedMatch:
    def __init__(self):
        pass

    def get_correlation(self) -> str:
        # Implement this method as needed
        raise NotImplementedError("Method not implemented")

    def get_source_address(self) -> int:
        # Implement this method as needed
        raise NotImplementedError("Method not implemented")

    def get_source_function(self) -> object:  # Replace with a suitable Python type
        # Implement this method as needed
        raise NotImplementedError("Method not implemented")

    def get_destination_address(self) -> int:
        # Implement this method as needed
        raise NotImplementedError("Method not implemented")

    def get_destination_function(self) -> object:  # Replace with a suitable Python type
        # Implement this method as needed
        raise NotImplementedError("Method not implemented")
```

Note that I've replaced the Java-specific types (e.g., `VTRelatedMatchType`, `Address`, and `Function`) with more general Python types. You'll need to implement these methods according to your specific use case, and replace the placeholder types (`object` in this example) with suitable Python classes or data structures.