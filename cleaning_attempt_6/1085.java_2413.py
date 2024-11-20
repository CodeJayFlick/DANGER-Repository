class RawEnumeratorImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # equivalent to OpaqueCleanable in Java
        self.jna_data = jna_data
        self.kind = None  # equivalent to ULONG in Java
        self.value = None  # equivalent to ModelObject in Java

    def get_pointer(self):
        return self.jna_data.get_pointer()  # equivalent to Pointer in Java

    def reset(self):
        COMUtils.check_rc(self.jna_data.reset())  # equivalent to void reset() in Java

    def next(self):
        bref = BSTRByReference()
        ul_kind = ULONGByReference()
        pp_value = PointerByReference()
        hr = self.jna_data.get_next(bref, ul_kind, pp_value)
        if hr == COMUtilsExtra.E_BOUNDS:
            return None
        COMUtils.check_rc(hr)

        self.kind = ul_kind.value

        wrap = WrapIModelObject(pp_value.value)
        try:
            value = ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

        bstr = bref.value
        key = bstr.value.decode('utf-8')  # equivalent to String in Java
        OleAuto.INSTANCE.sys_free_string(bstr)  # equivalent to SysFreeString in C++
        return key

    def get_kind(self):
        return ModelObjectKind.values()[self.kind]  # equivalent to ModelObjectKind in Java

    def get_value(self):
        return self.value  # equivalent to ModelObject in Java
