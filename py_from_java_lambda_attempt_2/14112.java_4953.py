Here is the translation of the given Java code into Python:

```Python
class LordBaelish:
    def __init__(self):
        pass

    def __init__(self, obs):
        super().__init__(obs)

    def time_passes(self, day: str) -> None:
        if day == 'Friday':
            self.notify_observers('STARK_SIGHTED')
```

Note that Python does not have direct equivalent of Java's `EventEmitter` and `Weekday`. I've used a simple string to represent the weekday in this translation. Also, there is no built-in support for events or observers in Python like it exists in Java with Observer pattern.