Here's how you can achieve this in Python:

```Python
class GdbState:
    NOT_STARTED = 0
    STARTING = 1
    STOPPED = 2
    RUNNING = 3
    EXIT = 4

    def __init__(self, state):
        self._state = state

    @property
    def is_alive(self):
        if self._state == GdbState.RUNNING or self._state == GdbState.STOPPED:
            return True
        elif self._state == GdbState.EXIT:
            return False
        else:  # NOT_STARTED, STARTING
            return True

# Example usage:

gdb_state = GdbState(GdbState.NOT_STARTED)
print(gdb_state.is_alive)  # Output: True

gdb_state = GdbState(GdbState.RUNNING)
print(gdb_state.is_alive)  # Output: True

gdb_state = GdbState(GdbState.EXIT)
print(gdb_state.is_alive)  # Output: False
```

This Python code defines a class `GdbState` with five possible states (`NOT_STARTED`, `STARTING`, `STOPPED`, `RUNNING`, and `EXIT`). Each state has an associated boolean property `is_alive`. The value of this property depends on the current state.