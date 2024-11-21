Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the Python equivalent of Java classes and methods. In particular:

* The `FVEventListener` and `FVEvent` classes are not part of the original code, but were added in the translation because they seem to be related to event handling.
* The `ActionEvent` class is not present in Python, so I removed it altogether.
* The `AbstractAction` class is also not present in Python, so I replaced it with a simple Python function (`actionPerformed`) that takes an `e` parameter (which is likely the equivalent of Java's `ActionEvent`).
* The rest of the code was translated as closely as possible to maintain its original functionality.