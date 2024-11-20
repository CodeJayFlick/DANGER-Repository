Here is the equivalent Python code:

```Python
class SBExecutionContext:
    def __init__(self):
        self.swig_cptr = None
        self.swig_cmemoown = False

    @staticmethod
    def get_cptr(obj):
        if obj is None:
            return 0
        else:
            return obj.swig_cptr

    def delete(self):
        if self.swig_cptr != 0:
            if self.swig_cmemoown:
                self.swig_cmemoown = False
                # call lldbJNI.delete_SBExecutionContext(self.swig_cptr)
            self.swig_cptr = 0

    @property
    def target(self):
        return SBTarget(lldbJNI.SBExecutionContext_GetTarget(self.swig_cptr, self), True)

    @property
    def process(self):
        return SBProcess(lldbJNI.SBExecutionContext_GetProcess(self.swig_cptr, self), True)

    @property
    def thread(self):
        return SBThread(lldbJNI.SBExecutionContext_GetThread(self.swig_cptr, self), True)

    @property
    def frame(self):
        return SBFrame(lldbJNI.SBExecutionContext_GetFrame(self.swig_cptr, self), True)
```

Note that I've made the following changes:

- The `finalize` method is not needed in Python as it's handled by the garbage collector.
- The `new_...__SWIG_*()` methods are replaced with constructors (`__init__`) and property getters (`@property`).
- The `swigCPtr` and `swigCMemOwn` fields are now instance variables, rather than being passed around as parameters to constructor-like methods.