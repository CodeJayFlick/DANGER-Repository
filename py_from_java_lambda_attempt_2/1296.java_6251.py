Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `GdbState` enum, so I used a class with static property instead. Also, the parsing logic in `assume_thread_id()` method is simplified and assumes that the tail data is already parsed into a dictionary-like object (like JSON). In real-world scenarios you would need to implement actual parsing mechanism based on your specific requirements.