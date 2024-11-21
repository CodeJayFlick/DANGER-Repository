Here is the translation of the given Java code into Python:

```Python
from enum import Enum

class NavigationHistoryChoices(Enum):
    NAVIGATION_EVENTS = "Navigation Events"
    VERTEX_CHANGES = "Vertex Changes"

    def __init__(self, display_name: str) -> None:
        self.display_name = display_name

    def __str__(self) -> str:
        return self.display_name
```

This Python code defines an Enum class `NavigationHistoryChoices` with two possible values: `NAVIGATION_EVENTS` and `VERTEX_CHANGES`. Each value has a corresponding string representation, which is stored in the `display_name` attribute. The `__init__` method initializes this attribute when each enum value is created.