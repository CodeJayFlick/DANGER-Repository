Here is the translation of the Java interface `CodeBlock` into a Python class:

```Python
class CodeBlock:
    def __init__(self):
        pass

    def get_first_start_address(self) -> 'Address':
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_start_addresses(self) -> list['Address']:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_name(self) -> str:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_flow_type(self) -> 'FlowType':
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_num_sources(self, monitor: object) -> int:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_sources(self, monitor: object) -> list['CodeBlock']:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_num_destinations(self, monitor: object) -> int:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_destinations(self, monitor: object) -> list['CodeBlock']:
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_model(self) -> 'CodeBlockModel':
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")
```

Note that I've used the `NotImplementedError` exception to indicate which methods have not been implemented yet. You'll need to fill in these methods with your own implementation based on how you want to use this class.

Also, note that Python does not support interfaces like Java's interface keyword. Instead, we can define a base class and then create abstract classes or classes that inherit from the base class.