Here is the translation of the given Java code into equivalent Python:

```Python
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

```

Please note that Python does not have direct equivalent of Java's `package`, `public class`, `extends` and other keywords. Also, Python is dynamically typed language so it doesn't require explicit declaration of types like in Java.