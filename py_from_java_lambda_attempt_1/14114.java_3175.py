Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import abc

class EventObserver(abc.ABC):
    pass

class Scout:
    def __init__(self, observer=None):
        if observer is not None:
            super().__init__(observer)

    def time_passes(self, day: str) -> None:
        if day == "TUESDAY":
            self.notify_observers("WARSHIPS_APPROACHING")

class EventEmitter(metaclass=abc.ABCMeta):
    @abstractmethod
    def notify_observers(self, event_name: str) -> None:
        pass

Weekday = {"MONDAY", "TUESDAY"}
```
Note that I had to make some assumptions about the `EventObserver` and `EventEmitter` classes since they were not fully defined in the original Java code. In Python, we don't need explicit getters and setters like we do in Java, so I omitted those as well.

Also, I used a dictionary (`Weekday`) instead of an enum (which doesn't exist in Python) to represent the weekdays.