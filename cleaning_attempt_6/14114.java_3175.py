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
