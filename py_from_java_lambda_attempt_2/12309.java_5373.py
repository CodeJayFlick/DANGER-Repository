Here is the translation of the Java code to Python:
```
class Float10DataType:
    dataType = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("float10", dtm)
        if not hasattr(self, 'dataType'):
            self.dataType = type(self)()

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return Float10DataType(dtm)

    @property
    def length(self):
        return 10

# Initialize the dataType attribute
Float10DataType.dataType = Float10DataType()
```
Note that I had to make some assumptions about the Python equivalent of Java concepts, such as:

* The `@Override` annotation is not needed in Python.
* The `public static final` fields are translated to a class-level variable with no explicit access modifier (since Python has no concept of public or private).
* The constructor (`__init__`) takes an optional argument `dtm`, which is used to initialize the parent class.