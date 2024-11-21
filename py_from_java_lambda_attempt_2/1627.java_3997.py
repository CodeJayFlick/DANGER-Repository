Here is the translation of the Java code to Python:
```
class LldbDebugOutputCallbacks:
    def __init__(self, manager):
        self.manager = manager

    def output(self, mask: int, text: str) -> None:
        self.manager.process_event(LldbConsoleOutputEvent(mask, text))

class LldbConsoleOutputEvent:
    def __init__(self, mask: int, text: str):
        self.mask = mask
        self.text = text
```
Note that I've kept the same class and method names as in the original Java code. In Python, we don't need to specify types for variables or function parameters like we do in Java, so I've omitted those parts.

Also, I've used the `__init__` special method to initialize the object's attributes (equivalent to a constructor in Java). The rest of the methods are straightforward translations from Java.