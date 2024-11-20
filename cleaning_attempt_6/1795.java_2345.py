class SBEvent:
    def __init__(self):
        self.swigCPtr = None
        self.swigCMemOwn = False

    @staticmethod
    def getCPtr(obj):
        return 0 if obj is None else obj.swigCPtr

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                lldbJNI.delete_SBEvent(self.swigCPtr)
            self.swigCPtr = 0
        self.swigCMemOwn = False

    @property
    def IsValid(self):
        return lldbJNI.SBEvent_IsValid(self.swigCPtr, self)

    @property
    def GetDataFlavor(self):
        return lldbJNI.SBEvent_GetDataFlavor(self.swigCPtr, self)

    @property
    def GetType(self):
        return lldbJNI.SBEvent_GetType(self.swigCPtr, self)

    @property
    def GetBroadcaster(self):
        return SBBroadcaster(lldbJNI.SBEvent_GetBroadcaster(self.swigCPtr, self), True)

    @property
    def GetBroadcasterClass(self):
        return lldbJNI.SBEvent_GetBroadcasterClass(self.swigCPtr, self)

    def BroadcasterMatchesRef(self, broadcaster):
        return lldbJNI.SBEvent_BroadcasterMatchesRef(self.swigCPtr, self, SBBroadcaster.getCPtr(broadcaster), broadcaster)

    def Clear(self):
        lldbJNI.SBEvent_Clear(self.swigCPtr, self)

    @staticmethod
    def GetCStringFromEvent(event):
        return lldbJNI.SBEvent_GetCStringFromEvent(SBEvent.getCPtr(event), event)

    def GetDescription(self, description):
        return lddbJNI.SBEvent_GetDescription(self.swigCPtr, self, SBStream.getCPtr(description), description)
