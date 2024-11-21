class DoubleComplexDataType:
    """Provides a definition of a complex built-in data type consisting of two double point numbers in the IEEE 754 double precision format."""
    
    def __init__(self):
        self.__data_type = "doublecomplex"
        
    @classmethod
    def get_data_type(cls) -> str:
        return cls().__data_type
    
    @staticmethod
    def clone(dtm: object) -> 'DoubleComplexDataType':
        if isinstance(dtm, type):
            return DoubleComplexDataType()
        else:
            return DoubleComplexDataType()

# Usage example:

if __name__ == "__main__":
    data_type = DoubleComplexDataType.get_data_type()
    print(data_type)
    
    dtm = "some data manager"
    cloned_data_type = DoubleComplexDataType.clone(dtm)
    print(cloned_data_type)
