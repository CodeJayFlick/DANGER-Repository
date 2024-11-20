Here is the translation of the Java code to Python:
```
class DbgCommandDoneEvent:
    def __init__(self):
        pass

    def __init__(self, cmd: 'DbgCommand') -> None:
        super().__init__()
        self.cmd = cmd

    @property
    def new_state(self) -> str:
        return "STOPPED"

    @property
    def command(self) -> 'DbgCommand':
        return self.cmd


class DbgCommand:
    pass


class DbgState:
    STOPPED = "STOPPED"
```
Note that I had to make some assumptions about the types and classes, as Python does not have an equivalent concept of packages or imports. Additionally, I used type hints for clarity, but they are not enforced by Python.

Also, in Java, `DbgCommand` is a class with a generic parameter `<?>`, which means it can take any type of argument. In Python, we don't need generics, so I simply defined the class without any parameters.