import logging

class BukkitLoggerFilter:
    _filter = None

    def __init__(self):
        self._filter = logging.Filter()
        Skript.close_on_disable(self._filter)

    @staticmethod
    def add_filter(f):
        if isinstance(f, logging.Filter):
            self._filter.add_filter(f)
        else:
            raise TypeError("f must be a Filter")

    @staticmethod
    def remove_filter(f):
        return self._filter.remove_filter(f)


# Usage example:

if __name__ == "__main__":
    filter = BukkitLoggerFilter()
    # Add filters here...
