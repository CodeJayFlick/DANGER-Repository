Here is the translation of the Java interface `LldbEvent` to a Python class:

```python
class LldbEvent:
    def __init__(self):
        pass

    def get_info(self) -> object:
        """Get the information detailing the event"""
        raise NotImplementedError("Subclasses must implement this method")

    def claim(self, cause: 'object') -> None:
        """Use LldbPendingCommand.claim(LldbEvent) instead
           @param cause the cause"""
        pass

    def get_cause(self) -> object:
        """If claimed, get the cause of this event
           @return the cause"""
        raise NotImplementedError("Subclasses must implement this method")

    def steal(self) -> None:
        """Use LldbPendingCommand.steal(LldbEvent) instead
           """
        pass

    def is_stolen(self) -> bool:
        """Check if this event is stolen
           A stolen event should not be processed further, except by the thief
           @return true if stolen, false otherwise"""
        return False  # default implementation: assume it's not stolen

    def new_state(self) -> 'StateType':
        """If this event implies a new lldb state, get that state
           @return the new state, or None for no change"""
        raise NotImplementedError("Subclasses must implement this method")
```

Note:

* I used Python 3.x syntax and conventions.
* The `object` type is used to represent Java's `T` (a generic type parameter) in Python. In Python, you can't specify a specific type for the `get_info`, `claim`, `get_cause`, and `new_state` methods because they are abstract methods that must be implemented by subclasses.
* The `StateType` class is not defined here; it's assumed to exist elsewhere in your codebase.