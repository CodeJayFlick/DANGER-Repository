Here is the translation of the Java interface `ToolConnection` into a Python class:

```Python
class ToolConnection:
    def __init__(self):
        pass

    def get_producer(self) -> 'PluginTool':
        """Get the tool that produces an event"""
        raise NotImplementedError("Method not implemented")

    def get_consumer(self) -> 'PluginTool':
        """Get the tool that consumes an event"""
        raise NotImplementedError("Method not implemented")

    def get_events(self) -> list:
        """Get the list of event names that is an intersection between what the producer produces and what the consumers consumes."""
        raise NotImplementedError("Method not implemented")

    def connect(self, eventName: str):
        """Connect the tools for the given event name"""
        raise NotImplementedError("Method not implemented")

    def disconnect(self, eventName: str):
        """Break the connection between the tools for the given event name"""
        raise NotImplementedError("Method not implemented")

    def is_connected(self, eventName: str) -> bool:
        """Return whether the tools are connected for the given event name"""
        raise NotImplementedError("Method not implemented")
```

Note that in Python, we don't have a direct equivalent of Java's `interface` keyword. Instead, we define an abstract base class (ABC) using the `abc` module or by raising `NotImplementedError`. In this case, I used the latter to indicate that each method should be implemented by any subclass.