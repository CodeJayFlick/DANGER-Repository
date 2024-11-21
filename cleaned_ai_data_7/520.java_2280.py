from ctypes import *

class WrapIDebugControl:
    def __init__(self):
        pass

    def __init__(self, pvInstance):
        self.pvInstance = pvInstance

    def GetInterrupt(self):
        return _invokeHR(0x0001, self.pvInstance)

    def SetInterrupt(self, Flags):
        return _invokeHR(0x0002, self.pvInstance, Flags)

    def GetInterruptTimeout(self, SecondsByReference):
        return _invokeHR(0x0003, self.pvInstance, SecondsByReference)

    def SetInterruptTimeout(self, Seconds):
        return _invokeHR(0x0004, self.pvInstance, Seconds)

    def ReturnInput(self, Buffer):
        return _invokeHR(0x0005, self.pvInstance, Buffer)

    def Output(self, Mask, Format, *objects):
        args = [self.pvInstance]
        for obj in objects:
            args.append(obj)
        return _invokeHR(0x0006, tuple(args))

    def OutputPrompt(self, OutputControl, Format, *objects):
        args = [self.pvInstance]
        args.append(OutputControl)
        for obj in objects:
            args.append(obj)
        return _invokeHR(0x0007, tuple(args))

    def GetPromptText(self, Buffer, BufferSize, TextSizeByReference):
        return _invokeHR(0x0008, self.pvInstance, Buffer, BufferSize, TextSizeByReference)

    def GetExecutionStatus(self, StatusByReference):
        return _invokeHR(0x0009, self.pvInstance, StatusByReference)

    def SetExecutionStatus(self, Status):
        return _invokeHR(0x0010, self.pvInstance, Status)

    def Evaluate(self, Expression, DesiredType, ValueByReference, RemainderIndexByReference):
        return _invokeHR(0x0011, self.pvInstance, Expression, DesiredType, ValueByReference, RemainderIndexByReference)

    def Execute(self, OutputControl, Command, Flags):
        return _invokeHR(0x0012, self.pvInstance, OutputControl, Command, Flags)

    def GetNumberBreakpoints(self, NumberByReference):
        return _invokeHR(0x0021, self.pvInstance, NumberByReference)

    def GetBreakpointByIndex(self, Index, BpByReference):
        return _invokeHR(0x0022, self.pvInstance, Index, BpByReference)

    def GetBreakpointById(self, Id, BpByReference):
        return _invokeHR(0x0023, self.pvInstance, Id, BpByReference)

    def AddBreakpoint(self, Type, DesiredId, BpByReference):
        return _invokeHR(0x0024, self.pvInstance, Type, DesiredId, BpByReference)

    def RemoveBreakpoint(self, Bp):
        return _invokeHR(0x0025, self.pvInstance, Bp)

    def WaitForEvent(self, Flags, Timeout):
        return _invokeHR(0x0031, self.pvInstance, Flags, Timeout)

    def GetLastEventInformation(self, TypeByReference, ProcessIdByReference, ThreadIdByReference,
                                 ExtraInformationByReference, ExtraInformationSize, TextSizeByReference, Buffer, BufferSize, DescriptionUsed):
        return _invokeHR(0x0032, self.pvInstance, TypeByReference, ProcessIdByReference, ThreadIdByReference,
                         ExtraInformationByReference, ExtraInformationSize, TextSizeByReference, Buffer, BufferSize, DescriptionUsed)

    def GetStackTrace(self, FrameOffset, StackOffset, InstructionOffset, Params, FrameSize, FramesFilled):
        return _invokeHR(0x0041, self.pvInstance, FrameOffset, StackOffset, InstructionOffset, Params, FrameSize, FramesFilled)

    def GetActualProcessorType(self, TypeByReference):
        return _invokeHR(0x0051, self.pvInstance, TypeByReference)

    def GetEffectiveProcessorType(self, TypeByReference):
        return _invokeHR(0x0061, self.pvInstance, TypeByReference)

    def GetExecutingProcessorType(self, TypeByReference):
        return _invokeHR(0x0071, self.pvInstance, TypeByReference)

    def GetDebuggeeType(self, ClassByReference, QualifierByReference):
        return _invokeHR(0x0081, self.pvInstance, ClassByReference, QualifierByReference)

    def GetNumberEventFilters(self, SpecificEvents, SpecificExceptions, ArbitraryExceptions):
        return _invokeHR(0x0091, self.pvInstance, SpecificEvents, SpecificExceptions, ArbitraryExceptions)

    def GetEventFilterText(self, Index, Buffer, BufferSize, TextSizeByReference):
        return _invokeHR(0x00A1, self.pvInstance, Index, Buffer, BufferSize, TextSizeByReference)

    def GetEventFilterCommand(self, Index, Buffer, BufferSize, CommandSizeByReference):
        return _invokeHR(0x00B1, self.pvInstance, Index, Buffer, BufferSize, CommandSizeByReference)

    def SetEventFilterCommand(self, Index, Command):
        return _invokeHR(0x00C1, self.pvInstance, Index, Command)

    def GetSpecificFilterParameters(self, Start, Count, Params):
        return _invokeHR(0x00D1, self.pvInstance, Start, Count, Params)

    def SetSpecificFilterParameters(self, Start, Count, Params):
        return _invokeHR(0x00E1, self.pvInstance, Start, Count, Params)

    def GetSpecificFilterArgument(self, Index, Buffer, BufferSize, ArgumentSizeByReference):
        return _invokeHR(0x00F1, self.pvInstance, Index, Buffer, BufferSize, ArgumentSizeByReference)

    def SetSpecificFilterArgument(self, Index, Argument):
        return _invokeHR(0x0101, self.pvInstance, Index, Argument)

    def GetExceptionFilterParameters(self, Count, Codes, Start, Params):
        return _invokeHR(0x0111, self.pvInstance, Count, Codes, Start, Params)

    def SetExceptionFilterParameters(self, Count, Params):
        return _invokeHR(0x0121, self.pvInstance, Count, Params)

    def GetExceptionFilterSecondCommand(self, Index, Buffer, BufferSize, CommandSizeByReference):
        return _invokeHR(0x0131, self.pvInstance, Index, Buffer, BufferSize, CommandSizeByReference)

    def SetExceptionFilterSecondCommand(self, Index, Command):
        return _invokeHR(0x0141, self.pvInstance, Index, Command)


def _invokeHR(index, *args):
    # implement the actual invocation of HR
    pass


class PointerByReference:
    def __init__(self, pvInstance):
        self.pvInstance = pvInstance

    @property
    def value(self):
        return self.pvInstance


class ULONG(Union):
    _fields_ = [("Value", c_ulong)]


class ULONGLONG(c_ulonglong)


def main():
    # usage example:
    wrap_idebug_control = WrapIDebugControl()
    result = wrap_idebug_control.GetInterrupt()
    print(result)

if __name__ == "__main__":
    main()

