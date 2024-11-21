Here is the translation of the Java code to Python:
```
class Float2DataType:
    dataType = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("float2", dtm)
        if not hasattr(self, "dataType"):
            self.dataType = self

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return Float2DataType(dtm)

    @property
    def length(self):
        return 2

# Create an instance of the class
Float2DataType.dataType = Float2DataType()
```
Note that I had to make some changes to accommodate Python's syntax and semantics. For example:

* In Java, `public static final` variables are equivalent to Python's `class attribute`. However, in Python, we don't need to specify `static` or `final`, as these concepts do not exist.
* The `@Override` annotation is not necessary in Python, as method overriding is implicit when a subclass provides an implementation for a method that exists in its superclass.
* In Java, the `getLength()` method returns an integer value. In Python, we can simply define a property called `length` using the `@property` decorator.

I hope this helps! Let me know if you have any further questions.