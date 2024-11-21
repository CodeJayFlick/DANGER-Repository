class IDataModelScriptDebug:
    IID_ = "DE8E0945-9750-4471-AB76-A8F79D6EC350"

    class VTIndices:
        GET_DEBUG_STATE = 0
        GET_CURRENT_POSITION = 1
        GET_STACK = 2
        SET_BREAKPOINT = 3
        FIND_BREAKPOINT_BY_ID = 4
        ENUMERATE_BREAKPOINTS = 5
        GET_EVENT_FILTER = 6
        SET_EVENT_FILTER = 7
        START_DEBUGGING = 8
        STOP_DEBUGGING = 9

    def script_debug_state(self):
        pass

    def get_debug_state(self):
        pass

    def current_position(self, currentPosition=None, positionSpanEnd=None, lineText=None):
        return None

    def get_stack(self):
        return None

    def set_breakpoint(self, linePosition=0, columnPosition=0, breakpoint=None):
        return None

    def find_breakpoint_by_id(self, breakpointId=0, breakpoint=None):
        return None

    def enumerate_breakpoints(self):
        return None

    def get_event_filter(self, eventFilter=0, isBreakEnabled=False):
        return None

    def set_event_filter(self, eventFilter=0, isBreakEnabled=True):
        pass

    def start_debugging(self, debugClient=None):
        return None

    def stop_debugging(self, debugClient=None):
        return None
