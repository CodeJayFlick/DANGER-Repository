class SBValue:
    def __init__(self):
        self.swig_cptr = 0
        self.swig_cmemoown = False

    @staticmethod
    def getCPtr(obj):
        return obj.swigCPtr if obj else 0

    def finalize(self, *args):
        self.delete()

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                lldbJNI.delete_SBValue(self.swigCPtr)
                self.swigCMemOwn = False
            self.swigCPtr = 0

    @property
    def IsValid(self):
        return lldbJNI.SBValue_IsValid(self.swigCPtr, self)

    @property
    def Clear(self):
        lldbJNI.SBValue_Clear(self.swigCPtr, self)

    # ... (rest of the methods are similar to above)
