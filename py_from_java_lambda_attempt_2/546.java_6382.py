Here is the translation of the Java code into equivalent Python:

```Python
from enum import Enum

class HRESULT(Enum):
    def __init__(self, value):
        self.value = value


class VTableIDebugEventCallbacks:
    FIELDS = ["QueryInterfaceCallback", "AddRefCallback", "ReleaseCallback",
              "GetInterestMaskCallback", "BreakpointCallback", "ExceptionCallback",
              "CreateThreadCallback", "ExitThreadCallback", "CreateProcessCallback",
              "ExitProcessCallback", "LoadModuleCallback", "UnloadModuleCallback",
              "SystemErrorCallback", "SessionStatusCallback", "ChangeDebuggeeStateCallback",
              "ChangeEngineStateCallback", "ChangeSymbolStateCallback"]

    def __init__(self):
        self.QueryInterfaceCallback = None
        self.AddRefCallback = None
        self.ReleaseCallback = None
        self.GetInterestMaskCallback = None
        self.BreakpointCallback = None
        self.ExceptionCallback = None
        self.CreateThreadCallback = None
        self.ExitThreadCallback = None
        self.CreateProcessCallback = None
        self.ExitProcessCallback = None
        self.LoadModuleCallback = None
        self.UnloadModuleCallback = None
        self.SystemErrorCallback = None
        self.SessionStatusCallback = None
        self.ChangeDebuggeeStateCallback = None
        self.ChangeEngineStateCallback = None
        self.ChangeSymbolStateCallback = None

    def getFieldOrder(self):
        return self.FIELDS


class GetInterestMaskCallback:
    def invoke(self, this_pointer: int, mask: int) -> HRESULT.value:


class BreakpointCallback:
    def invoke(self, this_pointer: int, bp: 'WrapIDebugBreakpoint') -> HRESULT.value:


class ExceptionCallback:
    def invoke(self, this_pointer: int, exception: 'EXCEPTION_RECORD64', first_chance: int) -> HRESULT.value:


class CreateThreadCallback:
    def invoke(self, this_pointer: int, handle: int, data_offset: int, start_offset: int) -> HRESULT.value:


class ExitThreadCallback:
    def invoke(self, this_pointer: int, exit_code: int) -> HRESULT.value:


class CreateProcessCallback:
    def invoke(self, this_pointer: int, image_file_handle: int, handle: int,
               base_offset: int, module_size: int, module_name: str, image_name: str,
               check_sum: int, time_date_stamp: int, initial_thread_handle: int,
               thread_data_offset: int, start_offset: int) -> HRESULT.value:


class ExitProcessCallback:
    def invoke(self, this_pointer: int, exit_code: int) -> HRESULT.value:


class LoadModuleCallback:
    def invoke(self, this_pointer: int, image_file_handle: int, base_offset: int,
               module_size: int, module_name: str, image_name: str, check_sum: int,
               time_date_stamp: int) -> HRESULT.value:


class UnloadModuleCallback:
    def invoke(self, this_pointer: int, image_base_name: str, base_offset: int) -> HRESULT.value:


class SystemErrorCallback:
    def invoke(self, this_pointer: int, error: int, level: int) -> HRESULT.value:


class SessionStatusCallback:
    def invoke(self, this_pointer: int, status: int) -> HRESULT.value:


class ChangeDebuggeeStateCallback:
    def invoke(self, this_pointer: int, flags: int, argument: int) -> HRESULT.value:


class ChangeEngineStateCallback:
    def invoke(self, this_pointer: int, flags: int, argument: int) -> HRESULT.value:


class ChangeSymbolStateCallback:
    def invoke(self, this_pointer: int, flags: int, argument: int) -> HRESULT.value:

```

Note that the Python code does not exactly match the Java code. The equivalent Python classes and methods are written in a way that is idiomatic to Python.