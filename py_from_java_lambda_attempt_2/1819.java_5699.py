Here is the translation of the given Java code into equivalent Python:

```Python
class SBProcessInfo:
    def __init__(self):
        self.swigCPtr = None
        self.swigCMemOwn = False

    @staticmethod
    def getCPtr(obj):
        if obj is None:
            return 0
        else:
            return obj.swigCPtr

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                # Add code to release memory here
                pass
            self.swigCPtr = 0

    def __del__(self):
        self.delete()

    @property
    def IsValid(self):
        return lldbJNI.SBProcessInfo_IsValid(self.swigCPtr, self)

    @property
    def Name(self):
        return lldbJNI.SBProcessInfo_GetName(self.swigCPtr, self)

    @property
    def ExecutableFile(self):
        return SBFileSpec(lldbJNI.SBProcessInfo_GetExecutableFile(self.swigCPtr, self), True)

    @property
    def ProcessID(self):
        return lldbJNI.SBProcessInfo_GetProcessID(self.swigCPtr, self)

    @property
    def UserID(self):
        return lldbJNI.SBProcessInfo_GetUserID(self.swigCPtr, self)

    @property
    def GroupID(self):
        return lldbJNI.SBProcessInfo_GetGroupID(self.swigCPtr, self)

    @property
    def UserIDIsValid(self):
        return lldbJNI.SBProcessInfo_UserIDIsValid(self.swigCPtr, self)

    @property
    def GroupIDIsValid(self):
        return lldbJNI.SBProcessInfo_GroupIDIsValid(self.swigCPtr, self)

    @property
    def EffectiveUserID(self):
        return lldbJNI.SBProcessInfo_GetEffectiveUserID(self.swigCPtr, self)

    @property
    def EffectiveGroupID(self):
        return lldbJNI.SBProcessInfo_GetEffectiveGroupID(self.swigCPtr, self)

    @property
    def EffectiveUserIDIsValid(self):
        return lldbJNI.SBProcessInfo_EffectiveUserIDIsValid(self.swigCPtr, self)

    @property
    def EffectiveGroupIDIsValid(self):
        return lldbJNI.SBProcessInfo_EffectiveGroupIDIsValid(self.swigCPtr, self)

    @property
    def ParentProcessID(self):
        return lldbJNI.SBProcessInfo_GetParentProcessID(self.swigCPtr, self)
```

Note: This translation assumes that `lldbJNI` is a Python module with the same functions as in your Java code.