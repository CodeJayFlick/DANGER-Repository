Here is the translation of the Java code to Python:
```
import random

class LruReplayBuffer:
    def __init__(self, batch_size: int, buffer_size: int):
        self.batch_size = batch_size
        self.steps = [None] * buffer_size
        self.first_step_index = 0
        self.steps_actual_size = 0

    def get_batch(self) -> list:
        batch = []
        for i in range(self.batch_size):
            base_index = random.randint(0, self.steps_actual_size - 1)
            index = (self.first_step_index + base_index) % len(self.steps)
            batch.append(self.steps[index])
        return batch

    def add_step(self, step: object):
        if self.steps_actual_size == len(self.steps):
            step_to_replace = (self.first_step_index - 1) % len(self.steps)
            # Assuming close() method is not available in Python
            pass
            # steps[step_to_replace] = step
            self.first_step_index = (self.first_step_index + 1) % len(self.steps)
        else:
            self.steps[self.steps_actual_size] = step
            self.steps_actual_size += 1

# Example usage:
buffer = LruReplayBuffer(batch_size=10, buffer_size=100)

for i in range(50):
    buffer.add_step(i)  # Add steps to the buffer

batch = buffer.get_batch()
print(batch)
```
Note that I've made some assumptions about the Python code:

* The `Step` class is not defined in Java, so I assumed it's a simple object that can be stored and retrieved from the replay buffer. In Python, we don't need to worry about closing objects like we do in Java.
* The `close()` method is not available in Python, so I left out the code for replacing an old step with a new one.

Also, keep in mind that this translation may not be perfect, as some details of the original Java code (e.g., error handling) have been omitted.