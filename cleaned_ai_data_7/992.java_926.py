import ctypes

class DataModelScriptHostContextImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # equivalent to OpaqueCleanable in Java
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def notify_script_change(self, script, change_kind):
        p_script = script.get_pointer()
        ul_change_kind = ctypes.c_ulong(change_kind)
        result = self.jna_data.notify_script_change(p_script, ul_change_kind)
        COMUtils.check_rc(result)

    def get_namespace_object(self):
        pp_namespace_object = PointerByReference()
        result = self.jna_data.get_namespace_object(pp_namespace_object)
        COMUtils.check_rc(result)

        wrap = WrapIModelObject(pp_namespace_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

class COMUtils:
    @staticmethod
    def check_rc(rc):
        # equivalent to COMUtils. checkRC in Java
        pass

class PointerByReference:
    def __init__(self):
        self.value = None  # equivalent to PointerByReference in Java

class WrapIModelObject:
    def __init__(self, value):
        self.value = value  # equivalent to WrapIModelObject in Java

    def query_interface(self):
        # equivalent to QueryInterface in Java
        pass

    def release(self):
        # equivalent to Release in Java
        pass
