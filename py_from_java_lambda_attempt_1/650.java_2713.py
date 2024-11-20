Here is the translation of the Java code to Python:
```
class DbgSetFilterSecondChanceCmdCommand:
    def __init__(self, manager: 'DbgManagerImpl', index: int, cmd: str):
        self.manager = manager
        self.index = index
        self.cmd = cmd

    def invoke(self) -> None:
        control = self.manager.get_control()
        control.set_exception_filter_second_command(self.index, self.cmd)
```
Note that I've used type hints for the `manager` parameter and the return value of the `invoke` method. This is not strictly necessary in Python 3.x, but it can help with code readability and static analysis tools.

Also, I've assumed that `DbgManagerImpl`, `DebugControl`, and other classes are defined elsewhere in your Python code or imported from a library. If you need to define these classes yourself, please let me know!