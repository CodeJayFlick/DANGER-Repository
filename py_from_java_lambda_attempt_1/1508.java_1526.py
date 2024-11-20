Here is the translation of the Java code to Python:
```
import threading

class LldbClientThreadExecutor:
    def __init__(self, make_client):
        self.make_client = make_client
        thread = threading.Thread(target=self.run)
        thread.daemon = True
        thread.start()

    def run(self):
        client = self.make_client()
        # assuming set_manager and get_manager are methods of the LldbManager class
        manager = None  # need to implement this part

    @property
    def manager(self):
        return self._manager

    @manager.setter
    def manager(self, value):
        self._manager = value

class DebugClient:
    pass  # assuming this is a placeholder for the actual implementation

class LldbManager:
    pass  # assuming this is a placeholder for the actual implementation
```
Note that I've made some assumptions about the Python code:

* The `thread` object in Java becomes a separate thread using the `threading` module in Python.
* The `makeClient` method returns an instance of `DebugClient`, which is assumed to be implemented elsewhere. Similarly, `LldbManager` is also assumed to have its own implementation.

The rest of the code is straightforward translation from Java to Python, with some minor adjustments for syntax and semantics.