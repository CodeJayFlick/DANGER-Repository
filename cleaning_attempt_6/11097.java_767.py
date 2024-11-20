import tkinter as tk

class PageDownAction:
    def __init__(self, event_listener):
        self.event_listener = event_listener

    def actionPerformed(self, e):
        # Now move the viewport down the distance of the viewport.
        page_down_evt = {"type": "VIEWPORT_PAGE_DOWN", "shifted": False}
        self.event_listener.send(page_down_evt)

class FVEventListener:
    def send(self, event):
        pass  # implement this method

# Example usage
event_listener = FVEventListener()
page_down_action = PageDownAction(event_listener)
