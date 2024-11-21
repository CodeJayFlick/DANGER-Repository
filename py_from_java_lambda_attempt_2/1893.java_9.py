Here is the translation of the given Java code into equivalent Python:

```Python
class TypeClass:
    eTypeClassInvalid = None
    eTypeClassArray = None
    eTypeClassBlockPointer = None
    eTypeClassBuiltin = None
    eTypeClassClass = None
    eTypeClassComplexFloat = None
    eTypeClassComplexInteger = None
    eTypeClassEnumeration = None
    eTypeClassFunction = None
    eTypeClassMemberPointer = None
    eTypeClassObjCObject = None
    eTypeClassObjCInterface = None
    eTypeClassObjCObjectPointer = None
    eTypeClassPointer = None
    eTypeClassReference = None
    eTypeClassStruct = None
    eTypeClassTypedef = None
    eTypeClassUnion = None
    eTypeClassVector = None
    eTypeClassOther = None
    eTypeClassAny = None

    def __init__(self, swig_name):
        self.swig_name = swig_name
        global type_class_next_value
        if not TypeClass.eTypeClassInvalid:
            for i in range(1, 22):  # assuming there are only 21 enum values
                setattr(TypeClass, f'eTypeClass{i}', None)
        self.swig_value = getattr(TypeClass, f'eTypeClass{swig_name.split(" ")[-1]}').swig_value + 1

    @classmethod
    def swig_to_enum(cls, swig_value):
        for value in dir(cls):
            if not value.startswith('eTypeClass') and int(getattr(cls, value).split('_')[2]) == swig_value:
                return getattr(cls, value)
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    def __str__(self):
        return self.swig_name

    @property
    def swig_value(self):
        return self._swig_value

    @swig_value.setter
    def swig_value(self, value):
        self._swig_value = value


type_class_next_value = 0

for i in range(1, 22):  # assuming there are only 21 enum values
    setattr(TypeClass, f'eTypeClass{i}', TypeClass(f"eTypeClass{i}", type_class_next_value))
    type_class_next_value += 1
```

Please note that Python does not support direct equivalent of Java's `enum` keyword. Instead, we use a class with static attributes to simulate the behavior of an enum in this translation.