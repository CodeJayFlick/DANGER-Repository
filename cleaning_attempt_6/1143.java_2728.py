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
