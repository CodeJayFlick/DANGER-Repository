Here is a translation of the Java code into equivalent Python:

```Python
import ctypes

class WrapIDebugClient4:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def OpenDumpFileWide(self, file_name: str, file_handle: int) -> int:
        return _invoke_hr(0x0001, self.pv_instance, file_name.encode('utf-16le'), file_handle)

    def WriteDumpFileWide(self, file_name: str, file_handle: int, qualifier: int, format_flags: int, comment: str) -> int:
        return _invoke_hr(0x0002, self.pv_instance, file_name.encode('utf-16le'), file_handle, qualifier, format_flags, comment.encode('utf-16le'))

    def AddDumpInformationFileWide(self, file_name: str, file_handle: int, type: int) -> int:
        return _invoke_hr(0x0003, self.pv_instance, file_name.encode('utf-16le'), file_handle, type)

    def GetNumberDumpFiles(self) -> int:
        number = ctypes.c_ulong()
        return _invoke_hr(0x0004, self.pv_instance, number)

    def GetDumpFile(self, index: int, buffer: bytes, buffer_size: int, name_size: ctypes.POINTER(ctypes.c_ulong), handle: ctypes.POINTER(ctypes.c_ulonglong), type: ctypes.POINTER(ctypes.c_ulong)) -> int:
        return _invoke_hr(0x0005, self.pv_instance, index, buffer, buffer_size, name_size, handle, type)

    def GetDumpFileWide(self, index: int, buffer: bytes, buffer_size: int, name_size: ctypes.POINTER(ctypes.c_ulong), handle: ctypes.POINTER(ctypes.c_ulonglong), type: ctypes.POINTER(ctypes.c_ulong)) -> int:
        return _invoke_hr(0x0006, self.pv_instance, index, buffer, buffer_size, name_size, handle, type)

def _invoke_hr(function_id: int, pv_instance: int, *args) -> int:
    # This function should be implemented based on the actual implementation
    pass

class ULONGLONG(ctypes.c_ulonglong):
    pass

class ULONG(ctypes.c_ulong):
    pass

class WString( bytes ):
    def __new__(cls, value : str):
        return super().__new__(value.encode('utf-16le'))

class HRESULT(int):
    pass
```

Please note that this is a translation of the Java code into equivalent Python. The actual implementation may vary based on your specific requirements and environment.

Also, please replace `_invoke_hr` function with your actual implementation as it seems to be calling some native method or library call which is not present in pure python.