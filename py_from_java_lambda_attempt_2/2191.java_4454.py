Here is a translation of the provided Java code into equivalent Python:

```Python
from enum import Enum

class TargetExecutionState(Enum):
    INACTIVE = 1
    ALIVE = 2
    STOPPED = 3
    RUNNING = 4
    TERMINATED = 5

    def is_alive(self) -> bool:
        if self == TargetExecutionState.INACTIVE or \
           self == TargetExecutionState.TERMINATED:
            return False
        else:
            return True

    def is_running(self) -> bool:
        if self == TargetExecutionState.RUNNING:
            return True
        elif self in [TargetExecutionState.ALIVE, TargetExecutionState.STOPPED]:
            return False
        else:
            raise ValueError("Invalid state")

    def is_stopped(self) -> bool:
        if self == TargetExecutionState.STOPPED or \
           self == TargetExecutionState.TERMINATED:
            return True
        elif self in [TargetExecutionState.INACTIVE, TargetExecutionState.RUNNING]:
            return False
        else:
            raise ValueError("Invalid state")


class ExecutionStateful:
    STATE_ATTRIBUTE_NAME = "state"

    def get_execution_state(self) -> 'TargetExecutionState':
        # Assuming you have a method to retrieve the attribute value.
        # Replace this with your actual implementation.
        return TargetExecutionState.INACTIVE
```

Please note that Python does not support Java-like interfaces or annotations. Instead, we define an `Enum` class for the execution states and implement methods on it. The `get_execution_state()` function is also implemented as a simple example; you would need to replace this with your actual implementation of retrieving the attribute value.