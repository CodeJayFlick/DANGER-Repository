import enum

class LogResult(enum.Enum):
    LOG = "LOG"
    CACHED = "CACHED"
    DO_NOT_LOG = "DO_NOT_LOG"

class LogHandler:
    def __init__(self):
        pass

    @abstractmethod
    def log(self, entry: dict) -> str:
        """Log an entry and return whether to print it or not"""
        raise NotImplementedError("Must be implemented by subclass")

    def on_stop(self):
        """Called just after the handler is removed from the active handlers stack"""
        pass

    def stop(self):
        """Stop this log handler"""
        SkriptLogger.remove_handler(self)
        self.on_stop()

    @property
    def stopped(self) -> bool:
        """Return whether this log handler has been stopped or not"""
        return SkriptLogger.is_stopped(self)

    def start(self) -> "LogHandler":
        """Start this log handler and return itself"""
        SkriptLogger.start_log_handler(self)
        return self

    def open(self):
        """Open (start) the log handler"""
        self.start()

    def close(self):
        """Close (stop) the log handler"""
        self.stop()
