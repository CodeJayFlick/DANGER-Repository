Here is the translation of the Java code to Python:
```
class DbgDebugOutputCallbacks:
    def __init__(self, manager):
        self.manager = manager

    def output(self, mask: int, text: str) -> None:
        # print(text)
        self.manager.process_event(DbgConsoleOutputEvent(mask, text))


class DbgConsoleOutputEvent:
    def __init__(self, mask: int, text: str):
        self.mask = mask
        self.text = text

# Example usage:
manager = ...  # initialize the manager object
callbacks = DbgDebugOutputCallbacks(manager)
callbacks.output(1, "Hello World!")
```
Note that I've used Python's built-in `print` function to simulate the output behavior, but you can modify this code as needed to fit your specific requirements.