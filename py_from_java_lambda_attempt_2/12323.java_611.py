Here is the translation of the Java code to Python:
```
class IconMaskResourceDataType:
    def __init__(self):
        self.__init__(None, "IconMaskResource", None)

    def __init__(self, path, name, dtm=None):
        super().__init__(path, name, dtm)

    @property
    def description(self):
        return "Icon with Mask stored as a Resource"

    def get_mnemonic(self, settings):
        return "IconMaskRes"

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return IconMaskResourceDataType(dtm)
```
Note that I've used Python's built-in `__init__` method to initialize the object, and also defined a property for the description. The rest of the methods are translated directly from Java.

Also, please note that this is not exactly equivalent code, as some concepts like static variables, serialization IDs, etc., do not have direct equivalents in Python.