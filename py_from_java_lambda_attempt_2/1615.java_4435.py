Here is the translation of the given Java code into Python:

```Python
class LldbStoppedEvent:
    def __init__(self, id):
        self.id = id

    def get_thread_id(self):
        return self.id

    def get_frame(self, thread):  # This method does not have a direct equivalent in Python as it is using Java's SBThread and SBFrame classes
        pass

class StateType:
    eStateStopped = 'stopped'

# Example usage:

event = LldbStoppedEvent('thread_id')
print(event.get_thread_id())  # prints: thread_id
```

Please note that the `get_frame` method in the original Java code is using Java's SBThread and SBFrame classes, which do not have direct equivalents in Python. Therefore, I've left it as a placeholder (`pass`) in the translation.