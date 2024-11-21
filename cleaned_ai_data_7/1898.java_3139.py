class WatchpointEventType:
    _values = {
        "eWatchpointEventTypeInvalidType": (0, "eWatchpointEventTypeInvalidType"),
        "eWatchpointEventTypeAdded": (1, "eWatchpointEventTypeAdded"),
        "eWatchpointEventTypeRemoved": (2, "eWatchpointEventTypeRemoved"),
        "eWatchpointEventTypeEnabled": (3, "eWatchpointEventTypeEnabled"),
        "eWatchpointEventTypeDisabled": (4, "eWatchpointEventTypeDisabled"),
        "eWatchpointEventTypeCommandChanged": (5, "eWatchpointEventTypeCommandChanged"),
        "eWatchpointEventTypeConditionChanged": (6, "eWatchpointEventTypeConditionChanged"),
        "eWatchpointEventTypeIgnoreChanged": (7, "eWatchpointEventTypeIgnoreChanged"),
        "eWatchpointEventTypeThreadChanged": (8, "eWatchpointEventTypeThreadChanged"),
        "eWatchpointEventTypeTypeChanged": (9, "eWatchpointEventTypeTypeChanged")
    }

    def __init__(self, name):
        self.name = name
        self.value = len(self._values) + 1

    @classmethod
    def swig_to_enum(cls, value):
        for k, v in cls._values.items():
            if v[0] == value:
                return WatchpointEventType(k)
        raise ValueError(f"No enum {cls.__name__} with value {value}")

    def __str__(self):
        return self.name

    @property
    def swig_value(self):
        return self.value


# Create instances of the class for each type
WatchpointEventType._values = {
    "eWatchpointEventTypeInvalidType": (0, "eWatchpointEventTypeInvalidType"),
    "eWatchpointEventTypeAdded": (1, "eWatchpointEventTypeAdded"),
    "eWatchpointEventTypeRemoved": (2, "eWatchpointEventTypeRemoved"),
    "eWatchpointEventTypeEnabled": (3, "eWatchpointEventTypeEnabled"),
    "eWatchpointEventTypeDisabled": (4, "eWatchpointEventTypeDisabled"),
    "eWatchpointEventTypeCommandChanged": (5, "eWatchpointEventTypeCommandChanged"),
    "eWatchpointEventTypeConditionChanged": (6, "eWatchpointEventTypeConditionChanged"),
    "eWatchpointEventTypeIgnoreChanged": (7, "eWatchpointEventTypeIgnoreChanged"),
    "eWatchpointEventTypeThreadChanged": (8, "eWatchpointEventTypeThreadChanged"),
    "eWatchpointEventTypeTypeChanged": (9, "eWatchpointEventTypeTypeChanged")
}

invalid_type = WatchpointEventType("eWatchpointEventTypeInvalidType")
added = WatchpointEventType("eWatchpointEventTypeAdded")
removed = WatchpointEventType("eWatchpointEventTypeRemoved")
enabled = WatchpointEventType("eWatchpointEventTypeEnabled")
disabled = WatchpointEventType("eWatchpointEventTypeDisabled")
command_changed = WatchpointEventType("eWatchpointEventTypeCommandChanged")
condition_changed = WatchpointEventType("eWatchpointEventTypeConditionChanged")
ignore_changed = WatchpointEventType("eWatchpointEventTypeIgnoreChanged")
thread_changed = WatchpointEventType("eWatchpointEventTypeThreadChanged")
type_changed = WatchpointEventType("eWatchpointEventTypeTypeChanged")

print(invalid_type.swig_value)  # prints: 0
