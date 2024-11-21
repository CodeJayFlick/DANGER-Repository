Here is the translation of the Java code to Python:
```
class DbgSetFilterCommand:
    def __init__(self, manager: 'DbgManager', index: int, cmd: str):
        self.manager = manager
        self.index = index
        self.cmd = cmd

    def invoke(self) -> None:
        control = self.manager.get_control()
        control.set_event_filter_command(self.index, self.cmd)
```
Note that I've used type hints for the `manager` parameter and the return value of the `invoke` method. This is not strictly necessary in Python 3.x, but it can help with code readability and static analysis tools.

Also, I've kept the same variable names as the original Java code to make it easier to compare the two versions.