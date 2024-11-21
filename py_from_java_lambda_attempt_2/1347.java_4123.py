Here is the translation of the given Java code into equivalent Python:

```Python
class GdbInfoOsCommand:
    def __init__(self, manager: 'GdbManagerImpl', type: str):
        self.manager = manager
        self.type = type

    def encode(self) -> str:
        return f"-info-os {self.type}"

    def complete(self, pending: 'GdbPendingCommand') -> 'GdbTable':
        done_event = pending.check_completion(GdbCommandDoneEvent)
        return GdbTable(done_event.assume_os_data_table(), "item")
```

Note that Python does not have direct equivalent of Java's package and import statements. The `class` keyword is used to define a class in Python, unlike Java where it is used for both classes and interfaces.

Also note the use of type hints (`-> str`, etc.) which are optional but can be useful for static analysis tools or IDEs that support them.