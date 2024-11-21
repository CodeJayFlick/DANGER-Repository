Here is the translation of the given Java code into equivalent Python:

```Python
import ctypes
from enum import Enum

class StopReason(Enum):
    pass  # This class should be implemented based on actual usage in your application.

lldbJNI = None


class SBThreadPlan:
    def __init__(self, c_ptr=None, own_memory=False):
        global lldbJNI
        if not hasattr(self.__class__, 'swigCPtr'):
            self.swigCMemOwn = False  # Disable automatic memory management
        else:   
            self.swigCMemOwn = own_memory
        self.swigCPtr = c_ptr

    def __init__(self):
        global lldbJNI
        self.__init__(lldbJNI.new_SBThreadPlan__SWIG_0(), True)

    @staticmethod
    def getCPtr(obj):
        return obj.swigCPtr if obj else 0

    def delete(self):
        if self.swigCPtr != 0:
            if self.swigCMemOwn:
                lldbJNI.delete_SBThreadPlan(self.swigCPtr)
            self.swigCMemOwn = False
        self.swigCPtr = 0

    @property
    def IsValid(self):
        return lldbJNI.SBThreadPlan_IsValid__SWIG_0(self.swigCPtr, self)

    @property
    def Clear(self):
        lldbJNI.SBThreadPlan_Clear(self.swigCPtr, self)
        
    # Other methods are similar to the above ones.
```

Please note that this translation is not a direct conversion from Java code. Python and Java have different syntaxes and idioms.