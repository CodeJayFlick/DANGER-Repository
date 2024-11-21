Here is the translation of the Java code to Python:
```
class ServiceListener:
    def __init__(self):
        pass

    def service_added(self, interface_class: type, service: object) -> None:
        """Notifies the listener that a service has been added to the tool."""
        ...

    def service_removed(self, interface_class: type, service: object) -> None:
        """Notifies the listener that a service has been removed from the tool."""
        ...
```
Note that I've used Python's built-in `type` and `object` types instead of Java's `Class<?>` and `Object`. Additionally, I've omitted any implementation details in the method bodies since they are not provided in the original code.