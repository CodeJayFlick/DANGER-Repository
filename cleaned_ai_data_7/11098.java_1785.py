import logging

class PageDownSelectionAction:
    def __init__(self, event_listener):
        self.event_listener = event_listener

    def actionPerformed(self, e):
        # Now move the viewport down the distance of the viewport.
        page_down_evt = {"type": "VIEWPORT_PAGE_DOWN", "is_page_down": True}
        self.event_listener.send(page_down_evt)
