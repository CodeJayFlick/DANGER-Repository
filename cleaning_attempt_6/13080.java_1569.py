class Callback:
    def __init__(self):
        pass

    @staticmethod
    def dummy():
        return lambda: None  # no-op

    @staticmethod
    def dummy_if_null(c=None):
        if c is None:
            return Callback.dummy()
        return c

    def call(self):
        raise NotImplementedError("Must be implemented by subclass")
