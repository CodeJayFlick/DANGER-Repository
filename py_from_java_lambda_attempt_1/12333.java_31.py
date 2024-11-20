Here is the translation of the Java code to Python:
```
class Integer6DataType:
    def __init__(self):
        self.__init__()

    def __init__(self, dtm=None):
        super().__init__("int6", True, dtm)

    @property
    def description(self):
        return "Signed 6-Byte Integer"

    @property
    def length(self):
        return 6

    def get_opposite_signedness_data_type(self):
        from . import UnsignedInteger6DataType
        return UnsignedInteger6DataType.dataType.clone(self.get_data_type_manager())

    def clone(self, dtm=None):
        if dtm == self.get_data_type_manager():
            return self
        return Integer6DataType(dtm)

    def get_c_type_declaration(self, data_organization=False):
        from . import getCTypeDeclaration
        return getCTypeDeclaration(self, True, data_organization, False)
```
Note that I've used Python's built-in `property` decorator to create read-only properties for the `description`, `length`, and other attributes. This is equivalent to Java's getter methods.

I've also removed the static final variable `dataType` since it doesn't have a direct equivalent in Python. Instead, you can define a separate class or function that returns an instance of this class if needed.

The rest of the code should be self-explanatory, with some minor adjustments to fit Python's syntax and semantics.