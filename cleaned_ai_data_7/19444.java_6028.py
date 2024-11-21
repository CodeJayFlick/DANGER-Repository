class EvtBookEdit:
    def __init__(self):
        pass

    @staticmethod
    def register_event():
        return {
            "name": "book edit",
            "description": "Called when a player edits a book.",
            "examples": ["on book edit:"],
            "since": "2.2-dev31"
        }

    def init(self, args):
        return True

    def check(self, event):
        if not isinstance(event, PlayerEditBookEvent) or event.is_signing():
            return False
        return True

    def __str__(self, event=None, debug=False):
        return "book edit"

class Skript:
    @staticmethod
    def register_event(name, cls, event_class, patterns):
        pass

class Literal:
    pass

class PlayerEditBookEvent:
    def is_signing(self):
        pass

# Usage example:

EvtBookEdit.register_event()
