import logging

class ArrowDownSelectionAction:
    def __init__(self, event_listener):
        self.event_listener = event_listener

    def perform_action(self):
        # Now fire off an event to tell any subscribers to perform the increment.
        event_type = "increment_and_add_selection"
        event_data = 1
        self.event_listener.send(event_type, event_data)
