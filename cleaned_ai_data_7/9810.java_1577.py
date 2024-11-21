class FilterTypeConverter:
    def __init__(self):
        pass

    @property
    def filter_type(self) -> type:
        """Returns the destination class of the conversion"""
        raise NotImplementedError("Subclasses must implement this method")

    def convert(self, column_type: object, settings: dict = None) -> object:
        """Converts an instance of the column type to an instance of the destination type"""
        raise NotImplementedError("Subclasses must implement this method")
