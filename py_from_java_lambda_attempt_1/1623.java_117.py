Here is the translation of the Java code into Python:

```Python
class LldbThreadSelectedEvent:
    def __init__(self, info):
        self.id = DebugClient.get_id(info.thread)
        self.state = info.thread.process().get_state()
        self.thread = info.thread
        self.frame = info.frame

    @property
    def thread_id(self):
        return self.id

    @property
    def state_type(self):
        return self.state

    @property
    def selected_thread(self):
        return self.thread

    @property
    def frame_selected(self):
        return self.frame


class DebugClient:
    @staticmethod
    def get_id(thread):
        # This method should be implemented based on the actual functionality of your Java code.
        pass


# Example usage:

info = {'thread': None, 'frame': None}  # You would replace this with actual data from lldb.

event = LldbThreadSelectedEvent(info)
print(event.thread_id)  # prints: <id>
print(event.state_type)  # prints: the state type
print(event.selected_thread)  # prints: the selected thread
print(event.frame_selected)   # prints: the frame
```

Please note that I have made some assumptions about how you would implement certain methods in Python, based on their Java counterparts.