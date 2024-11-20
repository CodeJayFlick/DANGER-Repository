class LldbAddSessionCommand:
    def __init__(self, manager):
        pass  # No direct equivalent in Python for super() call.

    def complete(self, pending=None) -> None:
        return None  # Not apparent this is needed

# Usage example:
manager = "Your Manager Implementation"
command = LldbAddSessionCommand(manager)
