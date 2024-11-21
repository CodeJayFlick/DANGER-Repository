import logging

class LoggerFilter:
    def __init__(self, logger):
        self.logger = logger
        self.old_filter = logger.getEffectiveLevel()
        logger.setLevel(self)

    def is_loggable(self, record):
        if self.old_filter and not self.old_filter(record.levelno):
            return False
        for f in self.filters:
            if not f.is_loggable(record):
                return False
        return True

    def add_filter(self, filter_):
        self.filters.append(filter_)

    def remove_filter(self, filter_):
        try:
            self.filters.remove(filter_)
        except ValueError:
            pass  # Filter was not found in the list

    def close(self):
        self.logger.setLevel(self.old_filter)
