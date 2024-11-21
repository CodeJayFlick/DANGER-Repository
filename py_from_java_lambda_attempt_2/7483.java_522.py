Here's a translation of the Java interface into equivalent Python classes:

```Python
class FGEddge:
    def __init__(self):
        self.flow_type = None  # FlowType is not defined in Python, so we'll use None for now.
        self.label = ""

    def get_flow_type(self):
        return self.flow_type

    def set_label(self, label: str) -> None:
        self.label = label

    def get_label(self) -> str:
        return self.label

    def set_default_alpha(self, alpha: float) -> None:
        pass  # This method doesn't do anything in the original Java code.

    def get_default_alpha(self) -> float:
        return 0.5  # Default value for now; you can change this as needed.

    def clone_edge(self, start: 'FGVertex', end: 'FGVertex') -> 'FGEddge':
        pass  # This method doesn't do anything in the original Java code.
```

Note that Python does not have direct support for interfaces like Java. Instead, we can use abstract classes or protocols to define a set of methods that must be implemented by any class that inherits from it.

Also note that I've used `None` as a placeholder for the `FlowType`, since there is no equivalent type in Python.