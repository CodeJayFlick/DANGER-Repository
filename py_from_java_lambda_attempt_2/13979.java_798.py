Here is the translation of the Java code to Python:
```
import logging

class MessageCollectorMember:
    def __init__(self, name):
        self.name = name
        self.messages = []

    @staticmethod
    def _log_info(message):
        logging.info(f"{name} sees message {message}")

    def accept(self, data):
        if isinstance(data, dict):  # equivalent to "data instanceof MessageData"
            self._handle_event(data)

    def _handle_event(self, data):
        self._log_info(data["message"])
        self.messages.append(data["message"])

    def get_messages(self):
        return self.messages.copy()
```
Note that I've used the `logging` module instead of SLF4J, and Python's built-in list type instead of Java's `ArrayList`. I've also replaced the `@Slf4j` annotation with a static method `_log_info`, since there is no direct equivalent to SLF4J in Python.