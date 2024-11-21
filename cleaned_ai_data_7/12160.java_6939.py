class EmptyAddressIterator:
    def __init__(self):
        pass

    def next(self):
        return None

    def has_next(self):
        return False

    def remove(self):
        raise UnsupportedOperationException()

    def __iter__(self):
        return self


# Define an exception class for compatibility with Java's UnsupportedOperationException
class UnsupportedOperationException(Exception):
    pass
