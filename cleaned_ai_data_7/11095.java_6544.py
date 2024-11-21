import logging

class HomeAction:
    def __init__(self, event_listener):
        self.event_listener = event_listener

    def actionPerformed(self, e):
        # First things first - turn off the tail state.
        if self.event_listener:
            self.event_listener.send(FVEvent(EventType.SROLL_LOCK_ON))

        # Now move the viewport down the distance of the viewport.
        self.event_listener.send(FVEvent(EventType.SROLL_HOME))


class FVEventListener:
    def send(self, event):
        pass


class FVEvent:
    def __init__(self, event_type, data=None):
        self.event_type = event_type
        self.data = data

    class EventType:
        SCROLL_LOCK_ON = 1
        SCROLL_HOME = 2
