Here is the equivalent Python code:

```Python
class StructuredDataType:
    eStructuredDataTypeInvalid = "eStructuredDataTypeInvalid"
    eStructuredDataTypeNull = "eStructuredDataTypeNull"
    eStructuredDataTypeGeneric = "eStructuredDataTypeGeneric"
    eStructuredDataTypeArray = "eStructuredDataTypeArray"
    eStructuredDataTypeInteger = "eStructuredDataTypeInteger"
    eStructuredDataTypeFloat = "eStructuredDataTypeFloat"
    eStructuredDataTypeBoolean = "eStructuredDataTypeBoolean"
    eStructuredDataTypeString = "eStructuredDataTypeString"
    eStructuredDataTypeDictionary = "eStructuredDataTypeDictionary"

    def __init__(self, swig_name):
        self.swig_name = swig_name
        StructuredDataType.swig_next += 1

    @classmethod
    def swig_to_enum(cls, swig_value):
        if 0 <= swig_value < len(StructuredDataType.swig_values) and \
           StructuredDataType.swig_values[swig_value].swig_name == str(swig_value):
            return StructuredDataType.swig_values[swig_value]
        for i in range(len(StructuredDataType.swig_values)):
            if StructuredDataType.swig_values[i].swig_name == str(i):
                return StructuredDataType.swig_values[i]
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    @classmethod
    def swig_to_enum_static(cls, swig_value):
        for i in range(len(StructuredDataType.swig_values)):
            if StructuredDataType.swig_values[i].swig_name == str(i) and \
               StructuredDataType.swig_values[i].swig_value == swig_value:
                return StructuredDataType.swig_values[i]
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    @classmethod
    def get_swig_next(cls):
        return cls.swig_next

    swig_values = [eStructuredDataTypeInvalid, eStructuredDataTypeNull,
                   eStructuredDataTypeGeneric, eStructuredDataTypeArray,
                   eStructuredDataTypeInteger, eStructuredDataTypeFloat,
                   eStructuredDataTypeBoolean, eStructuredDataTypeString,
                   eStructuredDataTypeDictionary]
    swig_next = 0
```

Note that Python does not have direct equivalent of Java's `public` and `private` access modifiers. The variables are directly accessible from outside the class in Python.