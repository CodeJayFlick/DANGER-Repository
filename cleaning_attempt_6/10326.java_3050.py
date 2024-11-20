class ShutdownPriority:
    FIRST = ShutdownPriority(-2147483648)
    DISPOSE_DATABASES = ShutdownPriority(1073741823 // 2)
    DISPOSE_FILE_HANDLES = ShutdownPriority(1073741823 // 2)
    SHUTDOWN_LOGGING = ShutdownPriority(1073741823 // 2)
    LAST = ShutdownPriority(2147483647)

    def __init__(self, priority):
        self.priority = priority

    def before(self):
        if self.priority == -2147483648:
            raise NoSuchElementException
        return ShutdownPriority(self.priority-1)

    def after(self):
        if self.priority == 2147483647:
            raise NoSuchElementException
        return ShutdownPriority(self.priority+1)

    def get_priority(self):
        return self.priority

class NoSuchElementException(Exception):
    pass
