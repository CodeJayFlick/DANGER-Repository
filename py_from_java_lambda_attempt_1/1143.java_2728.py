Here is the translation of the Java code to Python:
```python
import ctypes

class WrapIDataModelScriptHostContext:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def NotifyScriptChange(self, script, change_kind):
        # assume _invokeHR and VTIndices are defined elsewhere
        return _invoke_HR(VT_Indices.NOTIFY_SCRIPT_CHANGE, self.pv_instance, script, change_kind)

    def GetNamespaceObject(self, namespace_object_byref):
        # assume _invoke_HR is defined elsewhere
        return _invoke_HR(VT_Indices.GET_NAMESPACE_OBJECT, self.pv_instance, namespace_object_byref)
```
Note that I've made the following assumptions:

* `_invokeHR` and `VTIndices` are defined elsewhere in your Python code.
* The equivalent of Java's `PointerByReference` is not directly available in Python, so I used a simple reference to a `ctypes.POINTER` object instead.

Also note that this translation does not include the Apache License header or any other non-code elements from the original file.