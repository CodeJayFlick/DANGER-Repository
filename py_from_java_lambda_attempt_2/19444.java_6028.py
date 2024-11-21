Here is the equivalent Python code:

```Python
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
```

Please note that this translation assumes the following:

- The `Skript` class in Java has been replaced with a simple Python function.
- The `Literal` and `PlayerEditBookEvent` classes have been simplified to just their names, as there is no direct equivalent in Python.