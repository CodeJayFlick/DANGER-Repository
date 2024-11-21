Here is the translation of the Java code into Python:

```Python
import ctypes

class SBTypeCategory:
    def __init__(self):
        self.swigCPtr = None
        self.swigCMemOwn = False

    @staticmethod
    def getCPtr(obj):
        return obj.swigCPtr if obj else 0

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                ctypes.pythonapi.delete_SBTypeCategory.restype = None
                ctypes.pythonapi.delete_SBTypeCategory.argtypes = [ctypes.c_void_p]
                ctypes.pythonapi.delete_SBTypeCategory(self.swigCPtr)
                self.swigCMemOwn = False
            self.swigCPtr = 0

    def IsValid(self):
        return lldbJNI.SBTypeCategory_IsValid(self.swigCPtr, self)

    def GetEnabled(self):
        return lldbJNI.SBTypeCategory_GetEnabled(self.swigCPtr, self)

    def SetEnabled(self, arg0):
        lldbJNI.SBTypeCategory_SetEnabled(self.swigCPtr, self, arg0)

    def GetName(self):
        return lldbJNI.SBTypeCategory_GetName(self.swigCPtr, self)

    def GetLanguageAtIndex(self, idx):
        return LanguageType(lldbJNI.SBTypeCategory_GetLanguageAtIndex(self.swigCPtr, self, idx))

    def GetNumLanguages(self):
        return lldbJNI.SBTypeCategory_GetNumLanguages(self.swigCPtr, self)

    def AddLanguage(self, language):
        lldbJNI.SBTypeCategory_AddLanguage(self.swigCPtr, self, language.value)

    def GetDescription(self, description, description_level):
        return lldbJNI.SBTypeCategory_GetDescription(self.swigCPtr, self, SBStream.getCPtr(description), description, description_level.value)

    def GetNumFormats(self):
        return lldbJNI.SBTypeCategory_GetNumFormats(self.swigCPtr, self)

    def GetNumSummaries(self):
        return lldbJNI.SBTypeCategory_GetNumSummaries(self.swigCPtr, self)

    def GetNumFilters(self):
        return lldbJNI.SBTypeCategory_GetNumFilters(self.swigCPtr, self)

    def GetNumSynthetics(self):
        return lldbJNI.SBTypeCategory_GetNumSynthetics(self.swigCPtr, self)

    def GetTypeNameSpecifierForFilterAtIndex(self, arg0):
        return SBTypeNameSpecifier(lldbJNI.SBTypeCategory_GetTypeNameSpecifierForFilterAtIndex(self.swigCPtr, self, arg0), True)

    def GetTypeNameSpecifierForFormatAtIndex(self, arg0):
        return SBTypeNameSpecifier(lldbJNI.SBTypeCategory_GetTypeNameSpecifierForFormatAtIndex(self.swigCPtr, self, arg0), True)

    def GetTypeNameSpecifierForSummaryAtIndex(self, arg0):
        return SBTypeNameSpecifier(lldbJNI.SBTypeCategory_GetTypeNameSpecifierForSummaryAtIndex(self.swigCPtr, self, arg0), True)

    def GetTypeNameSpecifierForSyntheticAtIndex(self, arg0):
        return SBTypeNameSpecifier(lldbJNI.SBTypeCategory_GetTypeNameSpecifierForSyntheticAtIndex(self.swigCPtr, self, arg0), True)

    def GetFilterForType(self, arg0):
        return SBTypeFilter(lldbJNI.SBTypeCategory_GetFilterForType(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0), True)

    def GetFormatForType(self, arg0):
        return SBTypeFormat(lldbJNI.SBTypeCategory_GetFormatForType(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0), True)

    def GetSummaryForType(self, arg0):
        return SBTypeSummary(lldbJNI.SBTypeCategory_GetSummaryForType(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0), True)

    def GetSyntheticForType(self, arg0):
        return SBTypeSynthetic(lldbJNI.SBTypeCategory_GetSyntheticForType(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0), True)

    def GetFilterAtIndex(self, arg0):
        return SBTypeFilter(lldbJNI.SBTypeCategory_GetFilterAtIndex(self.swigCPtr, self, arg0), True)

    def GetFormatAtIndex(self, arg0):
        return SBTypeFormat(lldbJNI.SBTypeCategory_GetFormatAtIndex(self.swigCPtr, self, arg0), True)

    def GetSummaryAtIndex(self, arg0):
        return SBTypeSummary(lldbJNI.SBTypeCategory_GetSummaryAtIndex(self.swigCPtr, self, arg0), True)

    def GetSyntheticAtIndex(self, arg0):
        return SBTypeSynthetic(lldbJNI.SBTypeCategory_GetSyntheticAtIndex(self.swigCPtr, self, arg0), True)

    def AddTypeFormat(self, arg0, arg1):
        return lldbJNI.SBTypeCategory_AddTypeFormat(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0, SBTypeFormat.getCPtr(arg1), arg1)

    def DeleteTypeFormat(self, arg0):
        return lldbJNI.SBTypeCategory_DeleteTypeFormat(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0)

    def AddTypeSummary(self, arg0, arg1):
        return lldbJNI.SBTypeCategory_AddTypeSummary(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0, SBTypeSummary.getCPtr(arg1), arg1)

    def DeleteTypeSummary(self, arg0):
        return lldbJNI.SBTypeCategory_DeleteTypeSummary(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0)

    def AddTypeFilter(self, arg0, arg1):
        return lldbJNI.SBTypeCategory_AddTypeFilter(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0, SBTypeFilter.getCPtr(arg1), arg1)

    def DeleteTypeFilter(self, arg0):
        return lldbJNI.SBTypeCategory_DeleteTypeFilter(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0)

    def AddTypeSynthetic(self, arg0, arg1):
        return lldbJNI.SBTypeCategory_AddTypeSynthetic(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0, SBTypeSynthetic.getCPtr(arg1), arg1)

    def DeleteTypeSynthetic(self, arg0):
        return lddbJNI.SBTypeCategory_DeleteTypeSynthetic(self.swigCPtr, self, SBTypeNameSpecifier.getCPtr(arg0), arg0)

    def __str__(self):
        return lldbJNI.SBTypeCategory___str__(self.swigCPtr, self)
```

Note: This translation assumes that the Java code is using a SWIG-generated wrapper for C++ functions. The Python code uses ctypes to interface with these same C++ functions.