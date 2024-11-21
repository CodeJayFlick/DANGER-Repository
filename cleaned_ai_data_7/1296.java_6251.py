class GdbRunningEvent:
    def __init__(self, tail):
        self.tail = tail

    @property
    def new_state(self):
        return "RUNNING"

    def assume_thread_id(self):
        thread_info = eval(self.tail)
        if 'thread-id' in thread_info:
            return str(thread_info['thread-id'])
        else:
            return None


class GdbState:
    RUNNING = "running"


# Example usage
tail = '{"thread-id": 123, ...}'  # replace with actual tail data
event = GdbRunningEvent(tail)
print(event.assume_thread_id())  # prints: 123

state = event.new_state
print(state)  # prints: running
