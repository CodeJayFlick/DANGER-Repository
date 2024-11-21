class LogListener:
    def __init__(self):
        pass

    def message_logged(self, message: str, is_error: bool) -> None:
        """
        Called when a log message is received.

        Args:
            message (str): The message of the log event.
            is_error (bool): True if the message is considered an error,
                as opposed to an informational message.
        """
        pass
