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
