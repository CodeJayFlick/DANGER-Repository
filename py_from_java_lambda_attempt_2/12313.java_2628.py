Here is the translation of the Java code to Python:
```
class Float8DataType:
    dataType = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("float8", dtm)
        if not hasattr(self, "dataType"):
            self.dataType = type("Float8DataType", (object,), {"__module__": "ghidra.program.model.data"})

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return Float8DataType(dtm)

    @property
    def length(self):
        return 8

# Initialize the dataType attribute
Float8DataType.dataType = Float8DataType()
```
Note that I had to make some assumptions about the Python equivalent of Java concepts, such as:

* The `package` declaration is not necessary in Python.
* The `public` access modifier does not exist in Python (everything is public by default).
* The `@Override` annotation is not needed in Python, since method overriding works differently than in Java.

Also, I used the `super()` function to call the parent class's constructor, and the `__init__` method to initialize the object.