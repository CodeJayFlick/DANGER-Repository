class SBSymbolContextList:
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
                lldbJNI.delete_SBSymbolContextList(self.swigCPtr)
                self.swigCMemOwn = False
            self.swigCPtr = 0

    def __del__(self):
        self.delete()

    @property
    def IsValid(self):
        return lldbJNI.SBSymbolContextList_IsValid(self.swigCPtr, self)

    @property
    def GetSize(self):
        return lldbJNI.SBSymbolContextList_GetSize(self.swigCPtr, self)

    def GetContextAtIndex(self, idx):
        return SBSymbolContext(lldbJNI.SBSymbolContextList_GetContextAtIndex(self.swigCPtr, self, idx), True)

    def Append(self, sc):
        lldbJNI.SBSymbolContextList_Append__SWIG_0(self.swigCPtr, self, SBSymbolContext.getCPtr(sc), sc)

    def Append(self, sc_list):
        lldbJNI.SBSymbolContextList_Append__SWIG_1(self.swigCPtr, self, SBSymbolContextList.getCPtr(sc_list), sc_list)

    @property
    def GetDescription(self, description):
        return lldbJNI.SBSymbolContextList_GetDescription(self.swigCPtr, self, SBStream.getCPtr(description), description)

    def Clear(self):
        lldbJNI.SBSymbolContextList_Clear(self.swigCPtr, self)

    def __str__(self):
        return lldbJNI.SBSymbolContextList___str__(self.swigCPtr, self)
