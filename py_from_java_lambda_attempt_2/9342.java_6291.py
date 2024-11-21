Here is the translation of the Java interface `Droppable` into a Python class:

```python
class Droppable:
    def __init__(self):
        pass

    def is_drop_ok(self, e):
        """Return True if it's OK to drop the transferable at the location specified by the event"""
        return bool(e)  # Assuming DropTargetDragEvent has a truthy value for successful drops

    def drag_under_feedback(self, ok: bool, e):
        """Set drag feedback according to whether the drop action is OK or not"""
        pass  # No equivalent in Python; you might want to implement some GUI-related code here

    def undo_drag_under_feedback(self):
        """Revert back to normal if any drag feedback was set"""
        pass  # No equivalent in Python; you might want to implement some GUI-related code here

    def add(self, obj: object, e: 'DropTargetDropEvent', f: DataFlavor) -> None:
        """Add the object to the droppable component. The DropTargetAdapter calls this method from its drop() method"""
        pass  # No equivalent in Python; you might want to implement some GUI-related code here
```

Note that I've kept the `pass` statements as placeholders, since there is no direct translation of these methods into Python (e.g., Java's `DropTargetDragEvent`, `DataFlavor`). You would need to implement any necessary GUI or data transfer logic in your Python program.