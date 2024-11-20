class SBUnixSignals:
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
                self.swigCMemOwn = False
                lldbJNI.delete_SBUnixSignals(self.swigCPtr)
            self.swigCPtr = 0

    def Clear(self):
        lldbJNI.SBUnixSignals_Clear(self.swigCPtr, self)

    @property
    def IsValid(self):
        return lldbJNI.SBUnixSignals_IsValid(self.swigCPtr, self)

    def GetSignalAsCString(self, signo):
        return lldbJNI.SBUnixSignals_GetSignalAsCString(self.swigCPtr, self, signo)

    def GetSignalNumberFromName(self, name):
        return lldbJNI.SBUnixSignals_GetSignalNumberFromName(self.swigCPtr, self, name)

    @property
    def GetShouldSuppress(self, signo):
        return lldbJNI.SBUnixSignals_GetShouldSuppress(self.swigCPtr, self, signo)

    def SetShouldSuppress(self, signo, value):
        return lldbJNI.SBUnixSignals_SetShouldSuppress(self.swigCPtr, self, signo, value)

    @property
    def GetShouldStop(self, signo):
        return lddbJNI.SBUnixSignals_GetShouldStop(self.swigCPtr, self, signo)

    def SetShouldStop(self, signo, value):
        return lldbJNI.SBUnixSignals_SetShouldStop(self.swigCPtr, self, signo, value)

    @property
    def GetShouldNotify(self, signo):
        return lldbJNI.SBUnixSignals_GetShouldNotify(self.swigCPtr, self, signo)

    def SetShouldNotify(self, signo, value):
        return lldbJNI.SBUnixSignals_SetShouldNotify(self.swigCPtr, self, signo, value)

    @property
    def GetNumSignals(self):
        return lldbJNI.SBUnixSignals_GetNumSignals(self.swigCPtr, self)

    def GetSignalAtIndex(self, index):
        return lldbJNI.SBUnixSignals_GetSignalAtIndex(self.swigCPtr, self, index)
