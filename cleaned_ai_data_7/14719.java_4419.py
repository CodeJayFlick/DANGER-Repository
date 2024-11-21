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
