Here is the translation of the given Java code into equivalent Python:

```Python
class BasicType:
    eBasicTypeInvalid = None
    eBasicTypeVoid = None
    eBasicTypeChar = None
    eBasicTypeSignedChar = None
    eBasicTypeUnsignedChar = None
    eBasicTypeWChar = None
    eBasicTypeSignedWChar = None
    eBasicTypeUnsignedWChar = None
    eBasicTypeChar16 = None
    eBasicTypeChar32 = None
    eBasicTypeShort = None
    eBasicTypeUnsignedShort = None
    eBasicTypeInt = None
    eBasicTypeUnsignedInt = None
    eBasicTypeLong = None
    eBasicTypeUnsignedLong = None
    eBasicTypeLongLong = None
    eBasicTypeUnsignedLongLong = None
    eBasicTypeInt128 = None
    eBasicTypeUnsignedInt128 = None
    eBasicTypeBool = None
    eBasicTypeHalf = None
    eBasicTypeFloat = None
    eBasicTypeDouble = None
    eBasicTypeLongDouble = None
    eBasicTypeFloatComplex = None
    eBasicTypeDoubleComplex = None
    eBasicTypeLongDoubleComplex = None
    eBasicTypeObjCID = None
    eBasicTypeObjCClass = None
    eBasicTypeObjCSel = None
    eBasicTypeNullPtr = None
    eBasicTypeOther = None

    def __init__(self, swigName):
        self.swigName = swigName
        global BasicType_next_value
        if not hasattr(BasicType, 'next_value'):
            BasicType.next_value = 0
        self.swigValue = BasicType.next_value
        BasicType.next_value += 1

    def __init__(self, swigName, swigValue):
        self.swigName = swigName
        self.swigValue = swigValue
        global BasicType_next_value
        if not hasattr(BasicType, 'next_value'):
            BasicType.next_value = 0
        else:
            BasicType.next_value += 1

    def __str__(self):
        return self.swigName

    @classmethod
    def swigToEnum(cls, swigValue):
        for value in cls.__dict__.values():
            if isinstance(value, BasicType) and value.swigValue == swigValue:
                return value
        raise ValueError("No enum " + str(cls) + " with value " + str(swigValue))

    @classmethod
    def get_values(cls):
        values = []
        for key in cls.__dict__.keys():
            if isinstance(getattr(cls, key), BasicType):
                values.append(getattr(cls, key))
        return values

BasicType.eBasicTypeInvalid = BasicType("eBasicTypeInvalid", 0)
BasicType.eBasicTypeVoid = BasicType("eBasicTypeVoid")
for name in ["Char", "SignedChar", "UnsignedChar", "WChar", "SignedWChar", "UnsignedWChar",
             "Char16", "Char32", "Short", "UnsignedShort", "Int", "UnsignedInt", "Long", "UnsignedLong",
             "LongLong", "UnsignedLongLong", "Int128", "UnsignedInt128", "Bool", "Half", "Float", "Double", "LongDouble"]:
    setattr(BasicType, f"eBasicType{name}", BasicType(f"eBasicType{name}")
for name in ["FloatComplex", "DoubleComplex", "LongDoubleComplex", "ObjCID", "ObjCClass", "ObjCSel", "NullPtr", "Other"]:
    setattr(BasicType, f"eBasicType{name}", None)

print(BasicType.get_values())
```

Please note that Python does not have direct equivalent of Java's `enum` type. The above code uses a class with static variables to simulate the behavior of an enum in Java.