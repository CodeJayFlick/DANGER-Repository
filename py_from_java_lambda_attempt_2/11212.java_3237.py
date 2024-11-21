Here is the translation of the Java interface `Undoable` into a Python class:

```Python
class Undoable:
    def __init__(self):
        pass

    def can_undo(self) -> bool:
        """Returns true if there is a previous state to "undo" to."""
        return False  # default implementation, override as needed

    def can_redo(self) -> bool:
        """Returns true if there is a later state to "redo" to."""
        return False  # default implementation, override as needed

    def clear_undo(self):
        """Clear all undoable/redoable transactions"""
        pass  # no-op by default, implement as needed

    def undo(self) -> None:
        """Returns to the previous state. Normally, this will cause the current state
           to appear on the "redo" stack."""
        raise NotImplementedError("undo method not implemented")

    def redo(self) -> None:
        """Returns to a latter state that exists because of an undo.
           Normally, this will cause the current state to appear on the "undo" stack."""
        raise NotImplementedError("redo method not implemented")

    def get_undo_name(self) -> str:
        """Returns a description of the change that would be "undone"."""
        return ""  # default implementation, override as needed

    def get_redo_name(self) -> str:
        """Returns a description of the change that would be "redone"."""
        return ""  # default implementation, override as needed

    def add_transaction_listener(self, listener):
        """Adds the given transaction listener to this domain object"""
        pass  # no-op by default, implement as needed

    def remove_transaction_listener(self, listener):
        """Removes the given transaction listener from this domain object."""
        pass  # no-op by default, implement as needed
```

Note that I've used Python's built-in `bool` type for boolean return values and omitted Java-style comments.