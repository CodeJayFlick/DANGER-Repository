Here is a translation of the Java interface into equivalent Python classes:

```Python
class IDebugRegisters2:
    IID_IDEBUG_REGISTERS2 = "1656afa9-19c6-4e3a-97e7-5dc9160cf9c4"

    class VTIndices2:
        GET_DESCRIPTION_WIDE = 1
        GET_INDEX_BY_NAME_WIDE = 2
        GET_NUMBER_PSEUDO_REGISTERS = 3
        GET_PSEUDO_DESCRIPTION = 4
        GET_PSEUDO_DESCRIPTION_WIDE = 5
        GET_PSEUDO_INDEX_BY_NAME = 6
        GET_PSEUDO_INDEX_BY_NAME_WIDE = 7
        GET_PSEUDO_VALUES = 8
        SET_PSEUDO_VALUES = 9
        GET_VALUES2 = 10
        SET_VALUES2 = 11
        OUTPUT_REGISTERS2 = 12
        GET_INSTRUCTION_OFFSET2 = 13
        GET_STACK_OFFSET2 = 14
        GET_FRAME_OFFSET2 = 15

    def __init__(self):
        pass

    def GetDescriptionWide(self, Register, NameBuffer, NameBufferSize, NameSizeByRef, DescByRef):
        # implement this method in your Python code
        return None

    def GetIndexByNameWide(self, Name, IndexByRef):
        # implement this method in your Python code
        return None

    def GetNumberPseudoRegisters(self, NumberByRef):
        # implement this method in your Python code
        return None

    def GetPseudoDescription(self, Register, NameBuffer, NameBufferSize, NameSizeByRef, TypeModuleByRef, TypeIdByRef):
        # implement this method in your Python code
        return None

    def GetPseudoDescriptionWide(self, Register, NameBuffer, NameBufferSize, NameSizeByRef, TypeModuleByRef, TypeIdByRef):
        # implement this method in your Python code
        return None

    def GetPseudoIndexByName(self, Name, IndexByRef):
        # implement this method in your Python code
        return None

    def GetPseudoIndexByNameWide(self, Name, IndexByRef):
        # implement this method in your Python code
        return None

    def GetPseudoValues(self, Source, Count, Indices, Start, Values):
        # implement this method in your Python code
        return None

    def SetPseudoValues(self, Source, Count, Indices, Start, Values):
        # implement this method in your Python code
        return None

    def GetValues2(self, Source, Count, Indices, Start, Values):
        # implement this method in your Python code
        return None

    def SetValues2(self, Source, Count, Indices, Start, Values):
        # implement this method in your Python code
        return None

    def OutputRegisters2(self, OutputControl, Source, Flags):
        # implement this method in your Python code
        return None

    def GetInstructionOffset2(self, Source, OffsetByRef):
        # implement this method in your Python code
        return None

    def GetStackOffset2(self, Source, OffsetByRef):
        # implement this method in your Python code
        return None

    def GetFrameOffset2(self, Source, OffsetByRef):
        # implement this method in your Python code
        return None