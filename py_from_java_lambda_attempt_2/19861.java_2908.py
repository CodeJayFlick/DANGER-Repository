Here is the translation of the Java code into Python:

```Python
class EventValues:
    def __init__(self):
        pass

    class EventValueInfo(E):
        def __init__(self, event: E, c: type[T], getter: Getter[T, E], exclude_message: str = None, excludes: list[E] = None) -> None:
            self.event = event
            self.c = c
            self.getter = getter
            self.exclude_message = exclude_message
            self.excludes = excludes

        def get_event_class(self) -> type[E]:
            return self.event

        def get_value_class(self) -> type[T]:
            return self.c

        def get_excludes(self) -> list[type[E]]:
            if self.excludes is not None:
                return [type(x) for x in self.excludes]
            return []

        def get_exclude_error_message(self) -> str | None:
            return self.exclude_message

    default_event_values = []
    future_event_values = []
    past_event_values = []

    TIME_PAST = -1
    TIME_NOW = 0
    TIME_FUTURE = 1

    @staticmethod
    def get_event_values_list_for_time(time: int) -> list[EventValueInfo]:
        if time == EventValues.TIME_PAST:
            return EventValues.past_event_values
        elif time == EventValues.TIME_NOW:
            return EventValues.default_event_values
        elif time == EventValues.TIME_FUTURE:
            return EventValues.future_event_values
        else:
            raise ValueError("time must be -1, 0, or 1")

    @staticmethod
    def register_event_value(event: type[E], c: type[T], getter: Getter[T, E], time: int) -> None:
        for i in range(len(EventValues.get_event_values_list_for_time(time))):
            info = EventValues.get_event_values_list_for_time(time)[i]
            if not isinstance(info.event, event):
                continue
            return

    @staticmethod
    def get_event_value(event: E, c: type[T], time: int) -> T | None:
        getter = EventValues.get_event_value_getter(event.__class__, c, time)
        if getter is None:
            return None
        return getter.get(event)

    @staticmethod
    def get_event_value_getter(e: type[E], c: type[T], time: int, allow_default=True) -> Getter | None:
        event_values = EventValues.get_event_values_list_for_time(time)
        for ev in event_values:
            if not isinstance(ev.c, c):
                continue
            if check_excludes(ev, e):
                return (Getter[ev.c, E]) ev.getter

    @staticmethod
    def get_converted_getter(i: EventValueInfo[E, F], to: type[T], check_instance_of=True) -> Getter | None:
        converter = Converters.get_converter(i.c, to)
        if converter is None:
            return None
        return (Getter[to, E]) lambda e: converter.convert((i.getter).get(e))

    @staticmethod
    def does_event_value_have_time_states(event: type[E], c: type[T]) -> bool:
        return EventValues.get_event_value_getter(event, c, -1) is not None or EventValues.get_event_value_getter(event, c, 1) is not None

def check_excludes(ev: EventValueInfo, e: type[E]) -> bool | None:
    if ev.excludes is None:
        return True
    for ex in ev.excludes:
        if isinstance(ex, e):
            Skript.error(ev.exclude_message)
            return False
    return True
```

Please note that Python does not support Java's `@Nullable` and `@SafeVarargs`, so I removed them. Also, the type hints are used to indicate what types of variables each function parameter should be.