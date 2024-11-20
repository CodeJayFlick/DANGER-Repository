import logging

class CountingLogHandler(logging.Handler):
    def __init__(self, minimum_level: int):
        self.minimum = minimum_level
        self.count = 0

    def handle(self, record):
        if record.levelno >= self.minimum:
            self.count += 1
        return None

    def flush(self):
        pass

def start():
    logging.getLogger().addHandler(CountingLogHandler(logging.INFO))

class LogResult:
    LOG = "LOG"

# Example usage:
if __name__ == "__main__":
    handler = CountingLogHandler(logging.WARNING)
    logger = logging.getLogger()
    logger.addHandler(handler)

    for i in range(5):
        if i % 2 == 0:
            logger.warning("Warning message")
        else:
            logger.info("Info message")

    print(f"Count: {handler.count}")
