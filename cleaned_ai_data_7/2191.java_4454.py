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
