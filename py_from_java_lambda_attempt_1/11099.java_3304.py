Here is the translation of the Java code to Python:
```
import logging

class PageUpAction:
    def __init__(self, event_listener):
        self.event_listener = event_listener

    def actionPerformed(self, e):
        # First things first - turn off the tail state.
        # If the user interacts with the view controls, taling is deactivated.
        tail_off_evt = {"type": "SCROLL_LOCK_ON", "data": None}
        self.event_listener.send(tail_off_evt)

        # Now move the viewport up the distance of the viewport.
        move_up_evt = {"type": "VIEWPORT_PAGE_UP", "data": False}
        self.event_listener.send(move_up_evt)
```
Note that I've replaced Java-specific constructs like `public`, `private`, and `@Override` with Python's equivalent syntax. I've also converted the event listener interface to a simple dictionary-based system, as Python doesn't have built-in support for events or listeners.

Also, please note that this is just one possible translation of the code, and there may be other ways to achieve similar functionality in Python.