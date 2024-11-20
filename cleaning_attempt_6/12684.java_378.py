class ExternalReference:
    def __init__(self):
        pass

    def get_external_location(self) -> 'ExternalLocation':
        """Returns the object that represents the external location."""
        raise NotImplementedError("Method not implemented")

    def get_library_name(self) -> str:
        """Returns the name of the external library containing this location."""
        raise NotImplementedError("Method not implemented")

    def get_label(self) -> str | None:
        """Returns the external label associated with this location (may be null)."""
        raise NotImplementedError("Method not implemented")
