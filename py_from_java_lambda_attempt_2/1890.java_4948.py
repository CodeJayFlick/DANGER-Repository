Here is the translation of the given Java code into equivalent Python:

```Python
class SymbolType:
    eSymbolTypeAny = None
    eSymbolTypeInvalid = None
    eSymbolTypeAbsolute = "eSymbolTypeAbsolute"
    eSymbolTypeCode = "eSymbolTypeCode"
    eSymbolTypeResolver = "eSymbolTypeResolver"
    eSymbolTypeData = "eSymbolTypeData"
    eSymbolTypeTrampoline = "eSymbolTypeTrampoline"
    eSymbolTypeRuntime = "eSymbolTypeRuntime"
    eSymbolTypeException = "eSymbolTypeException"
    eSymbolTypeSourceFile = "eSymbolTypeSourceFile"
    eSymbolTypeHeaderFile = "eSymbolTypeHeaderFile"
    eSymbolTypeObjectFile = "eSymbolTypeObjectFile"
    eSymbolTypeCommonBlock = "eSymbolTypeCommonBlock"
    eSymbolTypeBlock = "eSymbolTypeBlock"
    eSymbolTypeLocal = "eSymbolTypeLocal"
    eSymbolTypeParam = "eSymbolTypeParam"
    eSymbolTypeVariable = "eSymbolTypeVariable"
    eSymbolTypeVariableType = "eSymbolTypeVariableType"
    eSymbolTypeLineEntry = "eSymbolTypeLineEntry"
    eSymbolTypeLineHeader = "eSymbolTypeLineHeader"
    eSymbolTypeScopeBegin = "eSymbolTypeScopeBegin"
    eSymbolTypeScopeEnd = "eSymbolTypeScopeEnd"
    eSymbolTypeAdditional = "eSymbolTypeAdditional"
    eSymbolTypeCompiler = "eSymbolTypeCompiler"
    eSymbolTypeInstrumentation = "eSymbolTypeInstrumentation"
    eSymbolTypeUndefined = None
    eSymbolTypeObjCClass = "eSymbolTypeObjCClass"
    eSymbolTypeObjCMetaClass = "eSymbolTypeObjCMetaClass"
    eSymbolTypeObjCIVar = "eSymbolTypeObjCIVar"
    eSymbolTypeReExported = "eSymbolTypeReExported"

    def __init__(self, swigName):
        self.swigName = swigName

    @classmethod
    def swigToEnum(cls, swigValue):
        if 0 <= swigValue < len(SymbolType.__dict__):
            return SymbolType(list(SymbolType.__dict__.values())[swigValue].name)
        for i in range(len(SymbolType.__dict__)):
            if list(SymbolType.__dict__.values())[i] == swigValue:
                return SymbolType(list(SymbolType.__dict__.keys())[i])
        raise ValueError(f"No enum {cls.__name__} with value {swigValue}")

    def __str__(self):
        return self.swigName

    @property
    def swigValue(self):
        return list(SymbolType.__dict__).index(self.swigName)
```

Please note that Python does not have direct equivalent of Java's `enum` type. However, we can achieve similar functionality using dictionaries and class methods in the above code.