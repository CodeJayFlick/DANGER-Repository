Here is the translation of the given Java code into equivalent Python:

```Python
class SBCompileUnit:
    def __init__(self):
        self.swigCPtr = None
        self.swigCMemOwn = False

    @staticmethod
    def getCPtr(obj):
        return 0 if obj is None else obj.swigCPtr

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                lldbJNI.delete_SBCompileUnit(self.swigCPtr)
                self.swigCMemOwn = False
            self.swigCPtr = 0

    def __del__(self):
        self.delete()

    def IsValid(self):
        return lldbJNI.SBCompileUnit_IsValid(self.swigCPtr, self)

    @property
    def FileSpec(self):
        if not hasattr(self, '_FileSpec'):
            self._FileSpec = SBFileSpec(lldbJNI.SBCompileUnit_GetFileSpec(self.swigCPtr, self), True)
        return self._FileSpec

    @property
    def NumLineEntries(self):
        return lldbJNI.SBCompileUnit_GetNumLineEntries(self.swigCPtr, self)

    def GetLineEntryAtIndex(self, idx):
        return SBLineEntry(lldbJNI.SBCompileUnit_GetLineEntryAtIndex(self.swigCPtr, self, idx), True)

    def FindLineEntryIndex(self, start_idx, line, inline_file_spec=None, exact=False):
        if not hasattr(self, '_inline_file_spec'):
            self._inline_file_spec = SBFileSpec(lldbJNI.SBCompileUnit_GetSupportFileAtIndex(self.swigCPtr, self, 0), True)
        return lldbJNI.SBCompileUnit_FindLineEntryIndex__SWIG_1(self.swigCPtr, self, start_idx, line, SBFileSpec.getCPtr(inline_file_spec or self._inline_file_spec), inline_file_spec or self._inline_file_spec if exact else None)

    @property
    def SupportFileAtIndex(self):
        return SBFileSpec(lldbJNI.SBCompileUnit_GetSupportFileAtIndex(self.swigCPtr, self, 0), True)

    @property
    def NumSupportFiles(self):
        return lldbJNI.SBCompileUnit_GetNumSupportFiles(self.swigCPtr, self)

    def FindSupportFileIndex(self, start_idx, sb_file=None, full=False):
        if not hasattr(self, '_sb_file'):
            self._sb_file = SBFileSpec(lldbJNI.SBCompileUnit_GetSupportFileAtIndex(self.swigCPtr, self, 0), True)
        return lldbJNI.SBCompileUnit_FindSupportFileIndex(self.swigCPtr, self, start_idx, SBFileSpec.getCPtr(sb_file or self._sb_file), sb_file or self._sb_file if full else None)

    @property
    def Types(self):
        if not hasattr(self, '_Types'):
            self._Types = SBTypeList(lldbJNI.SBCompileUnit_GetTypes__SWIG_0(self.swigCPtr, self, 0), True)
        return self._Types

    @property
    def Language(self):
        return lldbJNI.SBCompileUnit_GetLanguage(self.swigCPtr, self)

    def GetDescription(self, description):
        return lldbJNI.SBCompileUnit_GetDescription(self.swigCPtr, self, SBStream.getCPtr(description), description)

    def __str__(self):
        return lldbJNI.SBCompileUnit___str__(self.swigCPtr, self)
```

Note: The `lldbJNI` module is not a standard Python library and should be replaced with the actual implementation of your JNI interface.