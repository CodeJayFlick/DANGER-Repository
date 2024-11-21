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
