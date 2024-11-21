Here is a translation of the Java interface into equivalent Python code:

```Python
from enum import Enum

class VTIndices(Enum):
    GET_ID = 0
    GET_TYPE = 1
    GET_ADDER = 2
    GET_FLAGS = 3
    ADD_FLAGS = 4
    REMOVE_FLAGS = 5
    SET_FLAGS = 6
    GET_OFFSET = 7
    SET_OFFSET = 8
    GET_DATA_PARAMETERS = 9
    SET_DATA_PARAMETERS = 10
    GET_PASS_COUNT = 11
    SET_PASS_COUNT = 12
    GET_CURRENT_PASS_COUNT = 13
    GET_MATCH_THREAD_ID = 14
    SET_MATCH_THREAD_ID = 15
    GET_COMMAND = 16
    SET_COMMAND = 17
    GET_OFFSET_EXPRESSION = 18
    SET_OFFSET_EXPRESSION = 19
    GET_PARAMETERS = 20

class IDebugBreakpoint:
    IID_IDEBUG_BREAKPOINT = "5bd9d474-5975-423a-b88b-65a8e7110e65"

    def GetId(self):
        pass

    def GetType(self, BreakType=None, ProcType=None):
        return None

    def GetAdder(self):
        pass

    def GetFlags(self):
        return 0

    def AddFlags(self, Flags):
        pass

    def RemoveFlags(self, Flags):
        pass

    def SetFlags(self, Flags):
        pass

    def GetOffset(self):
        return 0

    def SetOffset(self, Offset):
        pass

    def GetDataParameters(self):
        return None

    def SetDataParameters(self, Size=None, AccessType=None):
        pass

    def GetPassCount(self):
        return 0

    def SetPassCount(self, Count):
        pass

    def GetCurrentPassCount(self):
        return 0

    def GetMatchThreadId(self):
        return 0

    def SetMatchThreadId(self, Thread):
        pass

    def GetCommand(self, Buffer=None, BufferSize=0, CommandSize=None):
        return None

    def SetCommand(self, Command):
        pass

    def GetOffsetExpression(self, Buffer=None, BufferSize=0, ExpressionSize=None):
        return None

    def SetOffsetExpression(self, Expression):
        pass

    def GetParameters(self):
        return None
```

Note that this translation is not a direct equivalent of the Java code. Python does not support interfaces or enums in the same way as Java. Instead, we use classes and subclasses to achieve similar functionality.