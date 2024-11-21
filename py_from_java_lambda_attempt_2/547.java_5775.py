Here is the translation of the Java code into equivalent Python:

```Python
from enum import Enum
import ctypes
import collections

class VTableIDebugEventCallbacksWide:
    FIELDS = ["QueryInterfaceCallback", "AddRefCallback", 
              "ReleaseCallback", "GetInterestMaskCallback",
              "BreakpointCallback", "ExceptionCallback", 
              "CreateThreadCallback", "ExitThreadCallback", 
              "CreateProcessCallback", "ExitProcessCallback", 
              "LoadModuleCallback", "UnloadModuleCallback", 
              "SystemErrorCallback", "SessionStatusCallback", 
              "ChangeDebuggeeStateCallback", "ChangeEngineStateCallback",
              "ChangeSymbolStateCallback"]

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
        return VTableIDebugEventCallbacksWide.FIELDS


class GetInterestMaskCallback(ctypes.WINFUNCTYPE(ctypes.c_ulong)):
    def __init__(self, thisPointer, Mask):
        pass  # This is a callback function and doesn't need to be implemented in Python

class BreakpointCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, Bp):
        pass  # This is a callback function and doesn't need to be implemented in Python

class ExceptionCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, Exception, FirstChance):
        pass  # This is a callback function and doesn't need to be implemented in Python

class CreateThreadCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, Handle, DataOffset, StartOffset):
        pass  # This is a callback function and doesn't need to be implemented in Python

class ExitThreadCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, ExitCode):
        pass  # This is a callback function and doesn't need to be implemented in Python

class CreateProcessCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, ImageFileHandle, Handle, BaseOffset, ModuleSize,
                 ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle,
                 ThreadDataOffset, StartOffset):
        pass  # This is a callback function and doesn't need to be implemented in Python

class ExitProcessCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, ExitCode):
        pass  # This is a callback function and doesn't need to be implemented in Python

class LoadModuleCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, ImageFileHandle, BaseOffset, ModuleSize,
                 ModuleName, ImageName, CheckSum, TimeDateStamp):
        pass  # This is a callback function and doesn't need to be implemented in Python

class UnloadModuleCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, ImageBaseName, BaseOffset):
        pass  # This is a callback function and doesn't need to be implemented in Python

class SystemErrorCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, Error, Level):
        pass  # This is a callback function and doesn't need to be implemented in Python

class SessionStatusCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, Status):
        pass  # This is a callback function and doesn't need to be implemented in Python

class ChangeDebuggeeStateCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, Flags, Argument):
        pass  # This is a callback function and doesn't need to be implemented in Python

class ChangeEngineStateCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, Flags, Argument):
        pass  # This is a callback function and doesn't need to be implemented in Python

class ChangeSymbolStateCallback(ctypes.WINFUNCTYPE(HRESULT)):
    def __init__(self, thisPointer, Flags, Argument):
        pass  # This is a callback function and doesn't need to be implemented in Python
```

Note that the `HRESULT` type is not defined in standard Python. It's likely an error code from Windows API.