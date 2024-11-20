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
