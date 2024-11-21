class SpyTaskMonitor:
    def __init__(self):
        self.messages = []
        self.recorder = None

    def set_recorder(self, recorder):
        self.recorder = recorder

    def record_message(self, message):
        if not hasattr(self, 'messages'):
            self.messages = []

        self.messages.append(message)
        if self.recorder:
            self.recorder.record(f"Monitor - {message}")

    def is_cancel_enabled(self):
        return True

    def clear_messages(self):
        self.messages.clear()

    def has_filter_message(self):
        for message in reversed(self.messages):
            if "Filtering" in message:
                return True
        return False

    def get_last_sort_message(self):
        for message in reversed(self.messages):
            if "Sorting" in message:
                return message
        assert False, "No sorting messages found"
        return None  # Can't reach here

    def messages_to_string(self):
        return str(self.messages)
