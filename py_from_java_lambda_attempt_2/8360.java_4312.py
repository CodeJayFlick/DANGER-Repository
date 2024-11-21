Here is the translation of the given Java code into Python:

```Python
class AbstractNestedTypeMsType:
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def nested_type_definition_record_number(self):
        return self._nested_type_definition_record_number

    @nested_type_definition_record_number.setter
    def nested_type_definition_record_number(self, value):
        self._nested_type_definition_record_number = value

    def emit(self, builder, bind):
        # No API for this.
        builder.append(self.name)
        pdb.get_type_record(self.nested_type_definition_record_number).emit(builder, bind)

class Pdb:
    def get_type_record(self, record_number):
        pass
```

Note that the Python code does not have direct equivalent of Java's abstract classes and interfaces. In Python, you can use a regular class or an interface implemented by other classes to achieve similar functionality.

Also note that I've used property decorators (`@property` and `@name.setter`) in the above Python code which is a way to implement getter and setter methods for attributes in Python.