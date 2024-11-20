Here is the translation of the Java interface `GTreeDragNDropHandler` to a Python class:
```python
class GTreeDragNDropHandler:
    def __init__(self):
        pass  # no initialization needed in this case

    def is_start_drag_ok(self, drag_user_data: list, drag_action: int) -> bool:
        """Return true if the drag user data can be dragged."""
        return True  # placeholder implementation; you'll need to implement this method

    def get_supported_drag_actions(self) -> int:
        """Returns the supported Drag actions for this tree. For available actions see DnDConstants."""
        return DnDConstants.ALL  # placeholder implementation; you'll need to implement this method

    def is_drop_site_ok(self, dest_user_data: object, flavors: list, drop_action: int) -> bool:
        """Return true if the drop site is valid for the given target."""
        return True  # placeholder implementation; you'll need to implement this method

    def drop(self, dest_user_data: object, transferable: dict, drop_action: int):
        """Add the given transferable's data to the destination user data."""
        pass  # no-op implementation; you'll need to implement this method
```
Note that I've used Python type hints where possible (e.g., `list`, `int`) and replaced Java-specific types like `DataFlavor` with more general Python types (`dict`). The placeholder implementations are just examples, as the actual logic will depend on your specific use case.