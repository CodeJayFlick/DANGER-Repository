class AnnotationHandler:
    def __init__(self):
        pass

    def get_prefix(self, e: 'Enum', member: str) -> str:
        """Returns the prefix for type Enum"""
        raise NotImplementedError("get_prefix")

    def get_suffix(self, e: 'Enum', member: str) -> str:
        """Returns the suffix for type Enum"""
        raise NotImplementedError("get_suffix")

    def get_prefix(self, c: 'Composite', dtc: 'DataTypeComponent') -> str:
        """Returns the prefix for type Composite"""
        raise NotImplementedError("get_prefix")

    def get_suffix(self, c: 'Composite', dtc: 'DataTypeComponent') -> str:
        """Returns the suffix for type Composite"""
        raise NotImplementedError("get_suffix")

    def get_description(self) -> str:
        """Returns the description of the specific handler"""
        return ""

    def get_language_name(self) -> str:
        """Returns the name of the C-ike language that this handler supports"""
        return ""

    def get_file_extensions(self) -> list[str]:
        """Returns an array of known extensions for the output file type.  If no extensions are 
           preferred, the an empty array should be returned."""
        return []

    def __str__(self) -> str:
        """Returns a string description of this handler"""
        return ""
