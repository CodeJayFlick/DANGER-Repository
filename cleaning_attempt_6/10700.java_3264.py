class SpyErrorDisplay:
    def __init__(self):
        self.messages = []

    def display_info_message(self, originator, parent, title, message):
        self.messages.append(f"INFO: {message}")

    def display_error_message(self, originator, parent, title, message, throwable):
        self.messages.append(f"ERROR: {message}")

    def display_warning_message(self, originator, parent, title, message, throwable):
        self.messages.append(f"WARNINIG: {message}")

    def __iter__(self):
        return iter(self.messages)

    def reset(self):
        self.messages = []

    def assert_display_message(self, *words):
        for message in self:
            if all(word.lower() in message.lower() for word in words):
                return
        fail(f"Did not find log message containing all these words: {', '.join(map(str, words))}\nInstead, had these messages: {self.messages}")

    def __str__(self):
        return str(self.messages)
