Here's your Java enum translated into a Python class:

```Python
class DbgState:
    NOT_STARTED = 0
    STARTING = 1
    STOPPED = 2
    RUNNING = 3
    EXIT = 4
    SESSION_EXIT = 5

    def __init__(self, value):
        self.value = value

    @property
    def is_alive(self):
        if self == DbgState.NOT_STARTED:
            return False
        elif self in [DbgState.STARTING, DbgState.STOPPED, DbgState.RUNNING]:
            return True
        else:
            return False


# Usage example:

dbg_state = DbgState.EXIT

print(dbg_state.is_alive)  # Output: False
```

This Python class `DbgState` has the same states as your Java enum. The `is_alive` property is used to determine if a state represents an alive or dead process/thread, based on its value.

Note that this implementation does not have the exact equivalent of Java's abstract method declaration in Python.