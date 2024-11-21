class Location:
    def __init__(self):
        pass

    def get_string_representation(self) -> str:
        """Returns a displayable representation of this location."""
        raise NotImplementedError("Must be implemented by subclass")

    def get_description(self) -> str:
        """Returns a description for the location. This should probably describe the significance of the
           location.
        """
        raise NotImplementedError("Must be implemented by subclass")

    def go(self, provider: object) -> bool:
        """Will attempt to navigate to the location as appropriate. For example, it may use the goto service
           to navigate the code browser to a progam and and address. Or it could launch a browser and display
           a web page.
        """
        raise NotImplementedError("Must be implemented by subclass")
