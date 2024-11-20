class Command:
    def __init__(self):
        pass

    def apply_to(self, obj: 'DomainObject') -> bool:
        """Applies the command to the given domain object."""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def status_msg(self) -> str:
        """Returns the status message indicating the status of the command."""
        return None

    @property
    def name(self) -> str:
        """Returns the name of this command."""
        raise NotImplementedError("Subclasses must implement this method")
