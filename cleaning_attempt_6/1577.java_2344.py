class AbstractLldbCompletedCommandEvent:
    def __init__(self, message=None):
        if message is None:
            super().__init__(None)
        else:
            super().__init__(message)

    def new_state(self) -> object:
        return None

# Usage example:
event = AbstractLlldbCompletedCommandEvent("Event occurred")
print(event.get_message())  # prints: Event occurred
