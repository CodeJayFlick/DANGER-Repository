class FloatComplexDataType:
    """Provides a definition of a complex built-in data type consisting of two floating point numbers in the IEEE 754 double precision format."""
    
    dataType = None
    
    def __init__(self):
        self.__init__(None)
        
    def __init__(self, dtm=None):
        super().__init__("floatcomplex", FloatDataType(), dtm)

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        else:
            return FloatComplexDataType(dtm)


class AbstractComplexDataType:
    pass


class FloatDataType:
    dataType = None

