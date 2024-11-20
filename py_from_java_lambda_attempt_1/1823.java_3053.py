Here is the translation of the given Java code into equivalent Python:

```Python
class SBSection:
    def __init__(self):
        self._swig_cptr = 0
        self._swig_cmemoown = False

    @property
    def _swig_cptr(self):
        return self.___c_ptr

    @_swig_cptr.setter
    def _swig_cptr(self, value):
        if not isinstance(value, int) or value < 0:
            raise TypeError("Invalid type for '_swig_cptr'. Expected: int")
        self.___c_ptr = value

    @property
    def _swig_cmemoown(self):
        return self._cmem_own

    @_swig_cmemoown.setter
    def _swig_cmemoown(self, value):
        if not isinstance(value, bool):
            raise TypeError("Invalid type for '_swig_cmemoown'. Expected: boolean")
        self._cmem_own = value

    @property
    def IsValid(self):
        return lldbJNI.SBSection_IsValid(self.___c_ptr)

    @property
    def GetName(self):
        return lldbJNI.SBSection_GetName(self.___c_ptr)

    def GetParent(self):
        return SBSection(lldbJNI.SBSection_GetParent(self.___c_ptr))

    def FindSubSection(self, sect_name):
        return SBSection(lldbJNI.SBSection_FindSubSection(self.___c_ptr, sect_name))

    @property
    def GetNumSubSections(self):
        return lldbJNI.SBSection_GetNumSubSections(self.___c_ptr)

    def GetSubSectionAtIndex(self, idx):
        return SBSection(lldbJNI.SBSection_GetSubSectionAtIndex(self.___c_ptr, idx))

    @property
    def GetFileAddress(self):
        return lldbJNI.SBSection_GetFileAddress(self.___c_ptr)

    def GetLoadAddress(self, target):
        return lldbJNI.SBSection_GetLoadAddress(self.___c_ptr, SBTarget.getCPtr(target), target)

    @property
    def GetByteSize(self):
        return lldbJNI.SBSection_GetByteSize(self.___c_ptr)

    @property
    def GetFileOffset(self):
        return lldbJNI.SBSection_GetFileOffset(self.___c_ptr)

    @property
    def GetFileByteSize(self):
        return lldbJNI.SBSection_GetFileByteSize(self.___c_ptr)

    def GetSectionData(self, offset=None, size=None):
        if offset is None and size is None:
            return SBData(lldbJNI.SBSection_GetSectionData__SWIG_0(self.___c_ptr))
        elif offset is not None and size is not None:
            return SBData(lldbJNI.SBSection_GetSectionData__SWIG_1(self.___c_ptr, offset, size))

    @property
    def GetSectionType(self):
        return SectionType.swigToEnum(lldbJNI.SBSection_GetSectionType(self.___c_ptr))

    @property
    def GetPermissions(self):
        return lldbJNI.SBSection_GetPermissions(self.___c_ptr)

    @property
    def GetTargetByteSize(self):
        return lldbJNI.SBSection_GetTargetByteSize(self.___c_ptr)

    def GetDescription(self, description):
        return lldbJNI.SBSection_GetDescription(self.___c_ptr, SBStream.getCPtr(description), description)

    def __str__(self):
        return lldbJNI.SBSection___str__(self.___c_ptr)
```

Please note that the above Python code is a direct translation of your given Java code. It may not be fully functional or error-free as it depends on various factors such as the actual implementation of `lldbJNI` and other classes used in this code, which are not provided here.