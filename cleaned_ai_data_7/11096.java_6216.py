import tkinter as tk

class MouseWheelAction:
    def __init__(self, event_listener):
        self.event_listener = event_listener

    def mouse_wheel_moved(self, e):
        # First things first - turn on scroll locking. If the user is moving the view,
        # don't have it snap back to the bottom every time new data comes in.
        scroll_lock_evt = FVEvent(EventType.SROLL_LOCK_ON, None)
        self.event_listener.send(scroll_lock_evt)

        # A notch is defined as a single row in the table. So scrolling one notch will
        # move the viewport by one row.
        notches = e.get_wheel_rotation()
        if notches < 0:
            move_up_evt = FVEvent(EventType.VIEWPORT_UP, -notches)
            self.event_listener.send(move_up_evt)
        else:
            move_down_evt = FVEvent(EventType.VIEWPORT_DOWN, notches)
            self.event_listener.send(move_down_evt)

class FVEventListener:
    def send(self, event):
        # TO DO: implement sending the event
        pass

class FVEvent:
    def __init__(self, event_type, data=None):
        self.event_type = event_type
        self.data = data

EventType = {
    'SCROLL_LOCK_ON': 0,
    'VIEWPORT_UP': 1,
    'VIEWPORT_DOWN': 2
}
