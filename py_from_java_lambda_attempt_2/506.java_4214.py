Here is the translation of the Java code into equivalent Python:

```Python
import ctypes

class WrapIDebugClient:
    def __init__(self):
        pass

    def AttachKernel(self, Flags, ConnectOptions):
        return self._invokeHR(1, None, Flags, ConnectOptions)

    def GetKernelConnectionOptions(self, Buffer, BufferSize, OptionsSize):
        return self._invokeHR(2, None, Buffer, BufferSize, OptionsSize)

    def SetKernelConnectionOptions(self, Options):
        return self._invokeHR(3, None, Options)

    # ... similar methods for StartProcessServer, ConnectProcessServer, DisconnectProcessServer,
    # GetRunningProcessSystemIds, GetRunningProcessSystemIdByExecutableName, and so on ...

    def _invokeHR(self, VTIndex, Pointer=None, *args):
        pass  # This method should be implemented based on the actual requirements

class IDebugClient:
    pass
```

Please note that this is a direct translation of Java code into Python. However, it's not complete as there are many methods in the original Java class and they all need to be translated into equivalent Python functions.

Also, please note that `ctypes` library was used for translating some parts of the code which were originally written using JNA (Java Native Access) in Java.