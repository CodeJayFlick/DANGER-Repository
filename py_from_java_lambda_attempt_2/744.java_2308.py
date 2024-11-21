Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `default` keyword in interface methods. Instead, we can use the same method name with different parameters to achieve similar functionality.

Also, Python is dynamically typed and it doesn't require explicit type declarations like Java. The above code assumes you are using static typing features provided by tools like mypy or typehinting for IDEs.