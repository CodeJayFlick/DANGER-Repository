from abc import ABCMeta, abstractmethod

class EventScope(metaclass=ABCMeta):
    @abstractmethod
    def get_event_thread(self) -> 'TargetThread':
        pass


class TargetEventType:
    STOPPED = 1 << 0
    RUNNING = 1 << 1
    PROCESS_CREATED = 1 << 2
    PROCESS_EXITED = 1 << 3
    THREAD_CREATED = 1 << 4
    THREAD_EXITED = 1 << 5
    MODULE_LOADED = 1 << 6
    MODULE_UNLOADED = 1 << 7
    BREAKPOINT_HIT = 1 << 8
    STEP_COMPLETED = 1 << 9
    EXCEPTION_OCCURRED = 1 << 10
    SIGNAL_RECEIVED = 1 << 11

class TargetEventScope:
    EVENT_OBJECT_ATTRIBUTE_NAME = "event_thread"

    def __init__(self):
        pass

    @property
    def event_type(self) -> int:
        return self._event_type

    @event_type.setter
    def event_type(self, value: int):
        self._event_type = value


class TargetThread:
    pass
