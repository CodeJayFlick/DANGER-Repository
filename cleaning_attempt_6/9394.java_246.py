class HelpDescriptor:
    def __init__(self):
        pass

    def get_help_object(self) -> object:
        """Returns the object for which help locations are defined."""
        raise NotImplementedError("Must be implemented by subclass")

    def get_help_info(self) -> str:
        """Returns a descriptive String about the help object that this descriptor represents."""
        raise NotImplementedError("Must be implemented by subclass")
