from struct import *

class DEBUG_BREAKPOINT_PARAMETERS(Structure):
    _fields_ = [("Offset", ULONGLONG),
               ("Id", ULONG),
               ("BreakType", ULONG),
               ("ProcType", ULONG),
               ("Flags", ULONG),
               ("DataSize", ULONG),
               ("DataType", ULONG),
               ("PassCount", ULONG),
               ("CurrentPassCount", ULONG),
               ("MatchThread", ULONG),
               ("CommandSize", ULONG),
               ("OffsetExpressionSize", ULONG)]

class DEBUG_REGISTER_DESCRIPTION(Structure):
    _fields_ = [("Type", ULONG),
               ("Flags", ULONG),
               ("SubregMaster", ULONG),
               ("SubregLength", ULONG),
               ("SubregMask", ULONGLONG),
               ("SubregShift", ULONG),
               ("Reserved0", ULONG)]

class DEBUG_VALUE(Union):
    _fields_ = [('u', INTEGER64), ('I8', UCHAR), 
                ('I16', USHORT), ('I32', ULONG), 
                ('I64', LONGLONG), ('F32', float), 
                ('F64', double), ('VI8', c_char_p)]

class DEBUG_MODULE_AND_ID(Structure):
    _fields_ = [("ModuleBase", ULONGLONG),
               ("Id", ULONGLONG)]

class DEBUG_MODULE_PARAMETERS(Structure):
    _fields_ = [("Base", ULONGLONG),
               ("Size", ULONG),
               ("TimeDateStamp", ULONG),
               ("Checksum", ULONG),
               ("Flags", ULONG),
               ("SymbolType", ULONG),
               ("ImageNameSize", ULONG),
               ("ModuleNameSize", ULONG),
               ("LoadedImageNameSize", ULONG),
               ("SymbolFileNameSize", ULONG),
               ("MappedImageNameSize", ULONG),
               ("Reserved0", ULONGLONG),
               ("Reserved1", ULONGLONG)]

class DEBUG_SYMBOL_ENTRY(Structure):
    _fields_ = [("ModuleBase", ULONGLONG),
               ("Offset", ULONGLONG),
               ("Id", ULONGLONG),
               ("Arg64", ULONGLONG),
               ("Size", ULONG),
               ("Flags", ULONG),
               ("TypeId", ULONG),
               ("NameSize", ULONG),
               ("Token", ULONG),
               ("Tag", ULONG),
               ("Arg32", ULONG),
               ("Reserved", ULONG)]

class DEBUG_THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [("Valid", ULONG),
               ("ExitStatus", ULONG),
               ("PriorityClass", ULONG),
               ("Priority", ULONG),
               ("CreateTime", ULONGLONG),
               ("ExitTime", ULONGLONG),
               ("KernelTime", ULONGLONG),
               ("UserTime", ULONGLONG),
               ("StartOffset", ULONGLONG),
               ("Affinity", ULONGLONG)]

class DEBUG_STACK_FRAME(Structure):
    _fields_ = [("InstructionOffset", ULONGLONG),
               ("ReturnOffset", ULONGLONG),
               ("FrameOffset", ULONGLONG),
               ("StackOffset", ULONGLONG),
               ("FuncTableEntry", ULONGLONG),
               ("Params", c_ulong * 4),
               ("Reserved", c_ulong * 6),
               ("Virtual", BOOL),
               ("FrameNumber", ULONG)]

class DEBUG_SPECIFIC_FILTER_PARAMETERS(Structure):
    _fields_ = [("ExecutionOption", ULONG),
               ("ContinueOption", ULONG),
               ("TextSize", ULONG),
               ("CommandSize", ULONG),
               ("ArgumentSize", ULONG)]

class DEBUG_EXCEPTION_FILTER_PARAMETERS(Structure):
    _fields_ = [("ExecutionOption", ULONG),
               ("ContinueOption", ULONG),
               ("TextSize", ULONG),
               ("CommandSize", ULONG),
               ("SecondCommandSize", ULONG),
               ("ExceptionCode", ULONG)]
