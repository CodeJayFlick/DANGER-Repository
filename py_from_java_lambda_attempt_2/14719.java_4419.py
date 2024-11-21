Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class MessageQueueManager:
    def __init__(self, initial_capacity):
        self.message_priority_queue = []

    def publish_message(self, message):
        self.message_priority_queue.append(message)

    def receive_message(self):
        if not self.message_priority_queue:
            return None
        return self.message_priority_queue.pop(0)
```
Note that I've removed the `PriorityMessageQueue` class and replaced it with a simple list (`self.message_priority_queue`) to store messages. The `publish_message` method appends new messages to the end of the queue, while the `receive_message` method removes and returns the first message from the front of the queue (or returns None if the queue is empty).