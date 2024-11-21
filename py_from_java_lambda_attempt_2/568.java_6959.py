Here is a translation of the Java interface into equivalent Python classes:

```Python
import ctypes
from enum import Enum

class VTableIndex(Enum):
    GET_NUMBER_REGISTERS = 3
    GET_DESCRIPTION = 4
    GET_INDEX_BY_NAME = 5
    GET_VALUE = 6
    SET_VALUE = 7
    GET_VALUES = 8
    SET_VALUES = 9
    OUTPUT_REGISTERS = 10
    GET_INSTRUCTION_OFFSET = 11
    GET_STACK_OFFSET = 12
    GET_FRAME_OFFSET = 13

class IDebugRegisters:
    IID_IDEBUG_REGISTERS = "ce289126-9e84-45a7-937e-67bb18691493"

    def __init__(self):
        pass

    def GetNumberRegisters(self, Number):
        raise NotImplementedError("GetNumberRegisters not implemented")

    def GetDescription(self, Register, NameBuffer, NameBufferSize, NameSize, Desc):
        raise NotImplementedError("GetDescription not implemented")

    def GetIndexByName(self, Name, Index):
        raise NotImplementedError("GetIndexByName not implemented")

    def GetValue(self, Register, Value):
        raise NotImplementedError("GetValue not implemented")

    def SetValue(self, Register, Value):
        raise NotImplementedError("SetValue not implemented")

    def GetValues(self, Count, Indices, Start, Values):
        raise NotImplementedError("GetValues not implemented")

    def SetValues(self, Count, Indices, Start, Values):
        raise NotImplementedError("SetValues not implemented")

    def OutputRegisters(self, OutputControl, Flags):
        raise NotImplementedError("OutputRegisters not implemented")

    def GetInstructionOffset(self, Offset):
        raise NotImplementedError("GetInstructionOffset not implemented")

    def GetStackOffset(self, Offset):
        raise NotImplementedError("GetStackOffset not implemented")

    def GetFrameOffset(self, Offset):
        raise NotImplementedError("GetFrameOffset not implemented")
```

This Python code defines an interface `IDebugRegisters` with methods that are similar to the Java interface. The `VTableIndex` class is also defined as a Python enum.

Note: In this translation, I used the `NotImplementedError` exception in each method of the `IDebugRegisters` class because these methods were not implemented in the original Java code and would need to be implemented separately for any specific use case.