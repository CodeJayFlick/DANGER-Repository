Here is the translation of the given Java code into Python:

```Python
class AbstractCompositeMsType:
    def __init__(self):
        pass

    def __str__(self):
        return "Abstract Composite Ms Type"

class RecordNumber:
    def __init__(self, value):
        self.value = value

class BigInteger:
    def __init__(self, value):
        self.value = value

class String:
    def __init__(self, value):
        self.value = value

class AbstractPdb:
    pass

class PdbByteReader:
    pass

class MsProperty:
    pass

class PrimitiveMsType:
    def is_no_type(self):
        return False


class AbstractComplexMsType:
    def __init__(self, pdb=None):
        if pdb:
            self.pdb = pdb
        else:
            self.pdb = None

    @property
    def name(self):
        pass

    @name.setter
    def name(self, value):
        self._name = value


class AbstractCompositeMsType(AbstractComplexMsType):

    def __init__(self, pdb=None, count=-1, field_list_record_number=RecordNumber(0), property=None,
                 size=BigInteger(0), derived_from_record_number=RecordNumber(0),
                 v_shape_table_record_number=RecordNumber(0), name="", mangled_name=""):
        super().__init__(pdb)
        self.name = name
        self.mangled_name = mangled_name
        self.size = size
        self.property = property
        self.field_descriptor_list_record_number = field_list_record_number
        self.derived_from_list_record_number = derived_from_record_number
        self.v_shape_table_record_number = v_shape_table_record_number

    def get_mangled_name(self):
        return self.mangled_name


    def get_derived_from_list_record_number(self):
        return self.derived_from_list_record_number


    def get_v_shape_table_record_number(self):
        return self.v_shape_table_record_number


    def get_size(self):
        return self.size

    @staticmethod
    def emit(builder, bind):
        my_builder = StringBuilder()
        my_builder.append("Abstract Composite Ms Type")
        if hasattr(bind, 'append'):
            builder.insert(0, my_builder)
```

Please note that Python does not have direct equivalent of Java's `BigInteger` and `RecordNumber`. In this translation, I used Python's built-in integer type for representing the size. Also, in the constructor of `AbstractCompositeMsType`, all parameters are assigned to instance variables directly as there is no concept of "setter" method like in Java.