from ctypes import *

class VTableIDebugEventContextCallbacks:
    FIELDS = ["QueryInterfaceCallback", "AddRefCallback", 
              "ReleaseCallback", "GetInterestMaskCallback",
              "BreakpointCallback", "ExceptionCallback", 
              "CreateThreadCallback", "ExitThreadCallback", 
              "CreateProcessCallback", "ExitProcessCallback", 
              "LoadModuleCallback", "UnloadModuleCallback", 
              "SystemErrorCallback", "SessionStatusCallback", 
              "ChangeDebuggeeStateCallback", "ChangeEngineStateCallback",
              "ChangeSymbolStateCallback"]

    class ByReference:
        pass

    QueryInterfaceCallback = WINFUNCTYPE(HRESULT, POINTER)
    AddRefCallback = WINFUNCTYPE(HRESULT)
    ReleaseCallback = WINFUNCTYPE(HRESULT)

    GetInterestMaskCallback = WINFUNCTYPE(HRESULT, POINTER, ULONG_PTR)
    BreakpointCallback = WINFUNCTYPE(HRESULT, POINTER, WrapIDebugBreakpoint2.ByReference, 
                                       POINTER, c_ulonglong)
    ExceptionCallback = WINFUNCTYPE(HRESULT, POINTER, EXCEPTION_RECORD64.ByReference, 
                                      c_bool, POINTER, c_ulonglong)

    CreateThreadCallback = WINFUNCTYPE(HRESULT, POINTER, ULONGLONG, ULONGLONG, ULONGLONG, 
                                         POINTER, c_ulonglong)
    ExitThreadCallback = WINFUNCTYPE(HRESULT, ULONG_PTR, POINTER, c_ulonglong)
    CreateProcessCallback = WINFUNCTYPE(HRESULT, ULONGLONG, ULONGLONG, ULONGLONG, ULONG, WString, 
                                          WString, ULONG, ULONG, ULONGLONG, ULONGLONG, ULONGLONG, 
                                          POINTER, c_ulonglong)

    ExitProcessCallback = WINFUNCTYPE(HRESULT, ULONG_PTR, POINTER, c_ulonglong)
    LoadModuleCallback = WINFUNCTYPE(HRESULT, ULONGLONG, ULONGLONG, ULONG, WString, WString, 
                                       ULONG, ULONG, POINTER, c_ulonglong)
    UnloadModuleCallback = WINFUNCTYPE(HRESULT, WString, ULONGLONG, POINTER, c_ulonglong)

    SystemErrorCallback = WINFUNCTYPE(HRESULT, ULONG_PTR, ULONG, POINTER, c_ulonglong)
    SessionStatusCallback = WINFUNCTYPE(HRESULT, ULONG_PTR)
    ChangeDebuggeeStateCallback = WINFUNCTYPE(HRESULT, ULONG_PTR, ULONGLONG, POINTER, 
                                                 c_ulonglong)
    ChangeEngineStateCallback = WINFUNCTYPE(HRESULT, ULONG_PTR, ULONGLONG, POINTER, 
                                              c_ulonglong)

    ChangeSymbolStateCallback = WINFUNCTYPE(HRESULT, ULONG_PTR, ULONGLONG)

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
        return VTableIDebugEventContextCallbacks.FIELDS
