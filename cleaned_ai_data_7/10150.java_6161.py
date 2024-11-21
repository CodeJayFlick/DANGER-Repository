class BasicFactory:
    def __init__(self):
        pass

    def create(self) -> object:
        """Creates an instance of T."""
        raise NotImplementedError("Subclasses must implement this method")

    def dispose(self, t: object) -> None:
        """Called when clients are finished with the given item and it should be disposed."""
        raise NotImplementedError("Subclasses must implement this method")
