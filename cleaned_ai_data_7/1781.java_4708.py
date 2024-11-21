class SBBreakpointList:
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
                lldbJNI.delete_SBBreakpointList(self.swigCPtr)
                self.swigCMemOwn = False
            self.swigCPtr = 0

    def __del__(self):
        self.delete()

    def __init__(self, target):
        this(self.lldbJNI.new_SBBreakpointList(SBTarget.getCPtr(target), target), True)

    @property
    def size(self):
        return lldbJNI.SBBreakpointList_GetSize(self.swigCPtr, self)

    def get_breakpoint_at_index(self, idx):
        return SBBreakpoint(lldbJNI.SBBreakpointList_GetBreakpointAtIndex(self.swigCPtr, self, idx), True)

    def find_breakpoint_by_id(self, arg0):
        return SBBreakpoint(lldbJNI.SBBreakpointList_FindBreakpointByID(self.swigCPtr, self, arg0), True)

    def append(self, sb_bkpt):
        lldbJNI.SBBreakpointList_Append(self.swigCPtr, self, SBBreakpoint.getCPtr(sb_bkpt), sb_bkpt)

    def append_if_unique(self, sb_bkpt):
        return lldbJNI.SBBreakpointList_AppendIfUnique(self.swigCPtr, self, SBBreakpoint.getCPtr(sb_bkpt), sb_bkpt)

    def append_by_id(self, id):
        lldbJNI.SBBreakpointList_AppendByID(self.swigCPtr, self, id)

    def clear(self):
        lldbJNI.SBBreakpointList_Clear(self.swigCPtr, self)
