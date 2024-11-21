class TestFailingErrorDisplayWrapper:
    def __init__(self):
        self.delegate = None

    def set_delegate(self, delegate):
        self.delegate = delegate

    def display_info_message(self, error_logger, originator, parent, title, message):
        if self.delegate is not None:
            self.delegate.display_info_message(error_logger, originator, parent, title, message)

    def display_error_message(self, error_logger, originator, parent, title, message, throwable=None):
        if not ConcurrentTestExceptionHandler.is_enabled():
            throwable = None
        if self.delegate is not None:
            self.delegate.display_error_message(error_logger, originator, parent, title, message, throwable)
        if throwable is not None:
            ConcurrentTestExceptionHandler.handle(throwable)

    def display_warning_message(self, error_logger, originator, parent, title, message, throwable=None):
        if not ConcurrentTestExceptionHandler.is_enabled():
            throwable = None
        if self.delegate is not None:
            self.delegate.display_warning_message(error_logger, originator, parent, title, message, throwable)
        if throwable is not None and isinstance(throwable, Exception):
            ConcurrentTestExceptionHandler.handle(throwable)

class ConcurrentTestExceptionHandler:
    _enabled = False

    @classmethod
    def set_enabled(cls, enabled):
        cls._enabled = enabled

    @classmethod
    def get_enabled(cls):
        return cls._enabled

    @classmethod
    def is_enabled(cls):
        return cls.get_enabled()

    @classmethod
    def handle(cls, thread, throwable=None):
        if not cls.is_enabled():
            return
        # Your code to handle the exception goes here.
