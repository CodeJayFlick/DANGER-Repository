import logging

class LogPanelAppender:
    def __init__(self, name: str, filter=None, layout=logging.Formatter()):
        self.name = name
        self.filter = filter
        self.layout = layout
        self.log_listener = None

    def append(self, event):
        if not self.log_listener:
            return
        level = event.levelname
        message = event.getMessage()
        is_error = level in ["ERROR", "FATAL"]
        self.log_listener.message_logged(message, is_error)

    @classmethod
    def create_appender(cls, name: str, layout=None, filter=None):
        if not name:
            logging.error("No name provided for LogPanelAppender")
            return None
        if not layout:
            layout = logging.Formatter()
        return cls(name, filter, layout)

    def set_log_listener(self, listener):
        self.log_listener = listener

if __name__ == "__main__":
    # Example usage
    appender = LogPanelAppender("My Appender", filter=logging.Filter(), layout=logging.Formatter())
    log_listener = MyLogListener()  # Replace with your implementation of LogListener
    appender.set_log_listener(log_listener)
