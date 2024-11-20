class DataService:
    def __init__(self):
        pass

    @property
    def description(self) -> str:
        return "Data creation service"

    def is_create_data_allowed(self, context: dict) -> bool:
        """
        Determine if create data is permitted on the specified location. If the 
        location is contained within the current program selection, the entire 
        selection is examined.

        Args:
            context (dict): The context containing program, location, and selection information

        Returns:
            bool: True if create data is allowed, else false.
        """
        return True  # Replace this with your actual logic

    def create_data(self, dt: dict, context: dict, enable_conflict_handling: bool) -> bool:
        """
        Apply the given data type at a location.

        Args:
            dt (dict): Data type to create at the location
            context (dict): The context containing program, location, and selection information
            enable_conflict_handling (bool): If true, the service may prompt the user to resolve data conflicts

        Returns:
            bool: True if the data could be created at the current location
        """
        return True  # Replace this with your actual logic
