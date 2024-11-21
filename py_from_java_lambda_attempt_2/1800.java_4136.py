Here is the translation of the given Java code into equivalent Python:

```Python
class SBFileSpecList:
    def __init__(self):
        self.swigCPtr = None
        self.swigCMemOwn = False

    @property
    def swigCPtr(self):
        return self._swigCPtr

    @swigCPtr.setter
    def swigCPtr(self, value):
        self._swigCPtr = value

    @property
    def swigCMemOwn(self):
        return self._swigCMemOwn

    @swigCMemOwn.setter
    def swigCMemOwn(self, value):
        self._swigCMemOwn = value

    def __del__(self):
        if self.swigCPtr is not None:
            delete()

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                self.swigCMemOwn = False
                lldbJNI.delete_SBFileSpecList(self.swigCPtr)
            self.swigCPtr = 0

    @classmethod
    def getCPtr(cls, obj):
        return (obj is None) and 0 or obj.swigCPtr

    def __init__(self, cptr=None, cmemown=False):
        if cptr is not None:
            self.swigCMemOwn = cmemown
            self.swigCPtr = cptr
        else:
            self.swigCPtr = lldbJNI.new_SBFileSpecList_0()
            self.swigCMemOwn = True

    def __init__(self, rhs):
        if rhs is not None:
            this(cldrJNl.new_SBFileSpecList_1(SBFileSpecList.getCPtr(rhs), rhs), True)
        else:
            this(lldbJNI.new_SBFileSpecList_0(), True)

    @property
    def getSize(self):
        return lldbJNI.SBFileSpecList_GetSize(self.swigCPtr, self)

    @property
    def getDescription(self, description):
        return lldbJNI.SBFileSpecList_GetDescription(self.swigCPtr, self, SBStream.getCPtr(description), description)

    def append(self, sb_file):
        lldbJNI.SBFileSpecList_Append(self.swigCPtr, self, SBFileSpec.getCPtr(sb_file), sb_file)

    @property
    def getAppendIfUnique(self, sb_file):
        return lldbJNI.SBFileSpecList_AppendIfUnique(self.swigCPtr, self, SBFileSpec.getCPtr(sb_file), sb_file)

    def clear(self):
        lldbJNI.SBFileSpecList_Clear(self.swigCPtr, self)

    @property
    def findFileIndex(self, idx, sb_file, full):
        return lldbJNI.SBFileSpecList_FindFileIndex(self.swigCPtr, self, idx, SBFileSpec.getCPtr(sb_file), sb_file, full)

    @property
    def getFileSpecAtIndex(self, idx):
        return SBFileSpec(lldbJNI.SBFileSpecList_GetFileSpecAtIndex(self.swigCPtr, self, idx), True)
```

Note: The `lldbJNI` and other classes (`SBStream`, `SBFileSpec`) are not defined in this code. They should be replaced with the actual Python equivalents or imported from a library that provides these functionalities.