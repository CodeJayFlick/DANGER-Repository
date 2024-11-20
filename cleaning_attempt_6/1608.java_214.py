class LldbRunningEvent:
    def __init__(self, id):
        self.id = id

    def get_thread_id(self):
        return self.id


class AbstractLldbEvent(str):
    pass


# Usage example:
event = LldbRunningEvent("thread-123")
print(event.get_thread_id())  # prints: thread-123
