Here's your Java enum translated into Python:

```Python
class EventTrigger:
    GUI_ACTION = "GUI action"
    API_CALL = "API call"
    MODEL_CHANGE = "Model change"
    INTERNAL_ONLY = "Internal use"

# You can also define it as an enumeration using the `enum` module in Python 3.4+
from enum import Enum

class EventTrigger(Enum):
    GUI_ACTION = "GUI action"
    API_CALL = "API call"
    MODEL_CHANGE = "Model change"
    INTERNAL_ONLY = "Internal use"
```

In this translation, I've kept the same names and descriptions as your Java code for consistency.