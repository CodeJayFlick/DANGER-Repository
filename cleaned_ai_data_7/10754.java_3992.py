class GraphJob:
    def __init__(self):
        pass

    def execute(self, listener):
        # implement this method in your subclass
        raise NotImplementedError("execute must be implemented by subclasses")

    def can_shortcut(self) -> bool:
        # implement this method in your subclass
        raise NotImplementedError("can_shortcut must be implemented by subclasses")

    def shortcut(self):
        # implement this method in your subclass
        raise NotImplementedError("shortcut must be implemented by subclasses")

    @property
    def is_finished(self) -> bool:
        return False

    def dispose(self):
        pass


class GraphJobListener:
    pass  # define the interface for a listener, if needed
