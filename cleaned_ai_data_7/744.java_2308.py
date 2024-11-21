class DbgModelTargetExecutionStateful:
    def convert_state(self, state: 'DbgState') -> 'TargetExecutionState':
        if isinstance(state, DbgState.RUNNING):
            return TargetExecutionState.RUNNING
        elif isinstance(state, (DbgState.STOPPED)):
            return TargetExecutionState.STOPPED
        else:
            raise ValueError("Invalid State")

    def set_execution_state(self, state: 'TargetExecutionState', reason: str) -> None:
        if self.is_valid():
            self.change_attributes([], {STATE_ATTRIBUTE_NAME: state}, reason)

class DbgModelTargetObject:
    pass

class TargetExecutionStateful:
    pass
