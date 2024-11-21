import logging

class FilteringLogHandler(logging.Handler):
    def __init__(self, minimum_level: int):
        self.minimum = minimum_level

    def handle(self, record: logging.LogRecord) -> None:
        if record.levelno >= self.minimum:
            return
        else:
            # equivalent to LogResult.DO_NOT_LOG in Java
            pass

    def flush(self) -> None:
        pass  # not implemented in the original code

def start(self) -> 'FilteringLogHandler':
    logging.getLogger().addHandler(self)
    return self
