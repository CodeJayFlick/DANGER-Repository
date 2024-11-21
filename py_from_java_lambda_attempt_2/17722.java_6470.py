Here is the translation of the Java interface `WriteLogNodeManager` to a Python class:
```python
import io

class WriteLogNodeManager:
    def __init__(self):
        pass

    def get_node(self, identifier: str) -> tuple:
        # Automatically create and return a WriteLogNode if it doesn't exist
        raise NotImplementedError("get_node not implemented")

    def delete_node(self, identifier: str) -> None:
        try:
            # Delete the log node. If it doesn't exist, this is an empty operation.
            pass  # TO DO: implement deletion logic
        except Exception as e:
            raise IOException(str(e))

    def close(self) -> None:
        # Close all nodes
        pass  # TO DO: implement closing logic
```
Note that I've used Python's type hints to indicate the expected types of the method parameters and return values. In particular, `get_node` returns a tuple (which is equivalent to Java's `WriteLogNode`) and `delete_node` raises an exception if something goes wrong.

The implementation details are left out for now, as they would require additional code that depends on specific requirements or dependencies not present in the original Java interface.