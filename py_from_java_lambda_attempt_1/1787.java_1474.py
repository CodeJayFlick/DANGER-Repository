Here is the translation of the given Java code into equivalent Python:

```Python
import ctypes

class SBCommandReturnObject:
    def __init__(self):
        self.swigCPtr = None
        self.swigCMemOwn = False

    @staticmethod
    def getCPtr(obj):
        return obj.swigCPtr if obj else 0

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                self.swigCMemOwn = False
                lldbJNI.delete_SBCommandReturnObject(self.swigCPtr)
            self.swigCPtr = 0

    def IsValid(self):
        return lldbJNI.SBCommandReturnObject_IsValid(self.swigCPtr, self)

    def GetOutput(self):
        return lldbJNI.SBCommandReturnObject_GetOutput__SWIG_0(self.swigCPtr, self).decode('utf-8')

    def GetError(self):
        return lldbJNI.SBCommandReturnObject_GetError__SWIG_0(self.swigCPtr, self).decode('utf-8')

    def GetOutputSize(self):
        return lldbJNI.SBCommandReturnObject_GetOutputSize(self.swigCPtr, self)

    def GetErrorSize(self):
        return lldbJNI.SBCommandReturnObject_GetErrorSize(self.swigCPtr, self)

    def GetOutput(self, only_if_no_immediate):
        return lldbJNI.SBCommandReturnObject_GetOutput__SWIG_1(self.swigCPtr, self, only_if_no_immediate).decode('utf-8')

    def GetError(self, if_no_immediate):
        return lldbJNI.SBCommandReturnObject_GetError__SWIG_1(self.swigCPtr, self, if_no_immediate).decode('utf-8')

    def PutOutput(self, file):
        return lldbJNI.SBCommandReturnObject_PutOutput__SWIG_0(self.swigCPtr, self, ctypes.c_longlong(file))

    def PutError(self, file):
        return lldbJNI.SBCommandReturnObject_PutError__SWIG_0(self.swigCPtr, self, ctypes.c_longlong(file))

    def Clear(self):
        lldbJNI.SBCommandReturnObject_Clear(self.swigCPtr, self)

    def SetStatus(self, status):
        lldbJNI.SBCommandReturnObject_SetStatus(self.swigCPtr, self, status.value())

    def SetError(self, error, fallback_error_cstr):
        lldbJNI.SBCommandReturnObject_SetError__SWIG_0(self.swigCPtr, self, ctypes.c_longlong(error), fallback_error_cstr)

    def SetError(self, error):
        lldbJNI.SBCommandReturnObject_SetError__SWIG_1(self.swigCPtr, self, ctypes.c_longlong(error))

    def SetError(self, error_cstr):
        lldbJNI.SBCommandReturnObject_SetError__SWIG_2(self.swigCPtr, self, error_cstr)

    def GetStatus(self):
        return ReturnStatus(lldbJNI.SBCommandReturnObject_GetStatus(self.swigCPtr, self))

    def Succeeded(self):
        return lldbJNI.SBCommandReturnObject_Succeeded(self.swigCPtr, self)

    def HasResult(self):
        return lldbJNI.SBCommandReturnObject_HasResult(self.swigCPtr, self)

    def AppendMessage(self, message):
        lldbJNI.SBCommandReturnObject_AppendMessage(self.swigCPtr, self, message.encode('utf-8'))

    def AppendWarning(self, message):
        lldbJNI.SBCommandReturnObject_AppendWarning(self.swigCPtr, self, message.encode('utf-8'))

    def GetDescription(self, description):
        return lldbJNI.SBCommandReturnObject_GetDescription(self.swigCPtr, self, ctypes.c_longlong(description), description)

    def SetImmediateOutputFile(self, file):
        if isinstance(file, SBFile):
            lldbJNI.SBCommandReturnObject_SetImmediateOutputFile__SWIG_0(self.swigCPtr, self, ctypes.c_longlong(file))
        elif hasattr(file, '__swig_cptr'):
            lldbJNI.SBCommandReturnObject_SetImmediateOutputFile__SWIG_1(self.swigCPtr, self, file.__swig_cptr)
        else:
            raise TypeError("Invalid type for SBFile")

    def SetImmediateErrorFile(self, file):
        if isinstance(file, SBFile):
            lldbJNI.SBCommandReturnObject_SetImmediateErrorFile__SWIG_0(self.swigCPtr, self, ctypes.c_longlong(file))
        elif hasattr(file, '__swig_cptr'):
            lldbJNI.SBCommandReturnObject_SetImmediateErrorFile__SWIG_1(self.swigCPtr, self, file.__swig_cptr)
        else:
            raise TypeError("Invalid type for SBFile")

    def __str__(self):
        return lldbJNI.SBCommandReturnObject___str__(self.swigCPtr, self).decode('utf-8')

    def SetImmediateOutputFile(self, BORROWED, transfer_ownership):
        if hasattr(BORROWED, '__swig_cptr'):
            lldbJNI.SBCommandReturnObject_SetImmediateOutputFile__SWIG_2(self.swigCPtr, self, BORROWED.__swig_cptr, transfer_ownership)
        else:
            raise TypeError("Invalid type for SBFile")

    def SetImmediateErrorFile(self, BORROWED, transfer_ownership):
        if hasattr(BORROWED, '__swig_cptr'):
            lldbJNI.SBCommandReturnObject_SetImmediateErrorFile__SWIG_2(self.swigCPtr, self, BORROWED.__swig_cptr, transfer_ownership)
        else:
            raise TypeError("Invalid type for SBFile")

    def PutCString(self, string, len):
        lldbJNI.SBCommandReturnObject_PutCString(self.swigCPtr, self, string.encode('utf-8'), ctypes.c_int(len))

    def Print(self, str):
        lldbJNI.SBCommandReturnObject_Print(self.swigCPtr, self, str.encode('utf-8'))
```

Please note that this is a translation of the given Java code into equivalent Python.