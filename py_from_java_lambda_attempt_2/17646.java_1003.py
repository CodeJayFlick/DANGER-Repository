Here is the translation of the Java interface `SyncServerManagerMBean` to a Python class:
```python
class SyncServerManagerMBean:
    def get_rpc_service_status(self):
        # implement this method in your subclass
        pass

    def get_rpc_port(self):
        # implement this method in your subclass
        pass

    def start_service(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def restart_service(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def stop_service(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that I've used the `raise NotImplementedError` statement to indicate that these methods are abstract and should be implemented by a subclass. In Python, we don't have an equivalent concept of interfaces like Java does, so we use abstract classes or protocols (which are not built-in in Python) to achieve similar functionality.

Also, since this is just a translation, I didn't include any specific implementation details for the methods, as those would depend on your actual requirements and use case.