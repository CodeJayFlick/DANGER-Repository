import logging

class InMemoryAppender:
    def __init__(self):
        self.log = []

    def start(self):
        pass  # No direct equivalent in Python's logging module

    def append(self, event_object: dict) -> None:
        self.log.append(event_object)

    def log_contains(self, message: str) -> bool:
        return any([event.get('message').lower().contains(message.lower()) for event in self.log])

# Usage
logger = logging.getLogger("root")
appender = InMemoryAppender()
logger.addHandler(appender)
