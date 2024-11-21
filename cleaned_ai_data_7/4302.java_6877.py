class BiDirectionStructure:
    def __init__(self):
        pass

    def get_negative_length(self) -> int:
        """Get the length of this DataType in the negative direction."""
        raise NotImplementedError("Method not implemented")

    def get_positive_length(self) -> int:
        """Get the length of this DataType in the positive direction."""
        raise NotImplementedError("Method not implemented")

    def get_split_offset(self) -> int:
        """Get the component offset which represents the division point between the positive and negative halves of the structure."""
        raise NotImplementedError("Method not implemented")

    def add_negative(self, data_type: object, length: int, name: str, comment: str) -> object:
        """Add a negative DataTypeComponent to this BiDirectionStructure"""
        raise NotImplementedError("Method not implemented")

    def add_positive(self, data_type: object, length: int, name: str, comment: str) -> object:
        """Add a positive DataTypeComponent to this BiDirectionStructure"""
        raise NotImplementedError("Method not implemented")
