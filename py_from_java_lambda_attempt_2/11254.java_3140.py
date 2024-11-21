Here is the translation of the Java code to Python:
```
class ServiceInterfaceImplementationPair:
    def __init__(self, interface_class: type, provider):
        self.interface_class = interface_class
        self.provider = provider
```
Note that I used the `type` hint for the `interface_class` parameter, since in Python we don't have a direct equivalent to Java's `Class<?>`. The `provider` parameter is simply an object of any type.