Here is the translation of the given Java code into equivalent Python:

```Python
class DbgFileExecAndSymbolsCommand:
    def __init__(self, manager: 'DbgManagerImpl', file: str):
        self.manager = manager
        self.file = file

    def invoke(self) -> None:
        # TODO Auto-generated method stub
        pass


from abc import ABC, abstractmethod


class AbstractDbgCommand(ABC):
    def __init__(self, manager: 'DbgManagerImpl'):
        self.manager = manager

    @abstractmethod
    def invoke(self) -> Void:
        pass


# Note that Python does not have a direct equivalent to Java's void type.
Void = None  # or any other appropriate return type for your command invocation method.

class DbgProcess:
    def file_exec_and_symbols(self, file: str):
        pass

class DbgManagerImpl:
    pass
```

Please note that the translation is not exact as Python and Java are different languages with their own syntax. The above code is an equivalent implementation of the given Java code in Python.