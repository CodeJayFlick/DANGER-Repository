Here is the equivalent Python code:

```Python
class ScheduledEvent:
    def __init__(self, world=None):
        self.world = world

    @property
    def world(self):
        return self._world

    @world.setter
    def world(self, value):
        if not isinstance(value, type(None)):
            assert isinstance(value, object), "World must be None or an instance of World"
        self._world = value


class HandlerList:
    pass


def register_event_value(event_class, world_class, getter):
    # TO DO: implement this function
    pass

# Usage example:

ScheduledEvent.register_event_value(ScheduledEvent, type(None), lambda e: e.world)
```

Please note that Python does not have direct equivalent of Java's `@Nullable` and `HandlerList`. The above code is a simple translation to the given Java code.