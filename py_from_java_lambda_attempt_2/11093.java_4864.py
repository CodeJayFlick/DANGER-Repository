Here is the translation of the given Java code into Python:

```Python
class FVEvent:
    class EventType(enum.Enum):
        COPY_SELECTION = "COPY_SELECTION"
        DECREMENT_SELECTION = "DECREMENT_SELECTION"
        DECREMENT_AND_ADD_SELECTION = "DECREMENT_AND_ADD_SELECTION"
        FILE_CHANGED = "FILE_CHANGED"
        INCREMENT_SELECTION = "INCREMENT_SELECTION"
        INCREMENT_AND_ADD_SELECTION = "INCREMENT_AND_ADD_SELECTION"
        OPEN_FILE_LOCATION = "OPEN_FILE_LOCATION"
        RELOAD_FILE = "RELOAD_FILE"
        SLIDER_CHANGED = "SLIDER_CHANGED"
        SCROLL_LOCK_OFF = "SCROLL_LOCK_OFF"
        SCROLL_LOCK_ON = "SCROLL_LOCK_ON"
        VIEWPORT_UPDATE = "VIEWPORT_UPDATE"
        VIEWPORT_UP = "VIEWPORT_UP"
        VIEWPORT_DOWN = "VIEWPORT_DOWN"
        VIEWPORT_PAGE_UP = "VIEWPORT_PAGE_UP"
        VIEWport_PAGE_DOWN = "VIEWPORT_PAGE_DOWN"
        SCROLL_HOME = "SCROLL_HOME"
        SCROLL_END = "SCROLL_END"
        SCROLL_END_2 = "SCROLL_END_2"

    def __init__(self, event_type: EventType, arg):
        self.event_type = event_type
        self.arg = arg

# Example usage:
event1 = FVEvent(FVEvent.EventType.COPY_SELECTION, "Example argument")
```

Please note that Python does not have an exact equivalent to Java's `enum` type. Instead, we use the built-in `Enum` class from the `enum` module in Python.