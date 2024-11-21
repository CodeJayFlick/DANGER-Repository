Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class CompositeEntity:
    def __init__(self):
        self.console = ConsoleCoarseGrainedObject()

    def set_data(self, message: str, signal: str) -> None:
        self.console.set_data(message, signal)

    def get_data(self) -> list[str]:
        return self.console.get_data()

    def init(self) -> None:
        self.console.init()
```
Note that I've used Python's type hints for the `set_data` and `get_data` methods to indicate their expected input types.