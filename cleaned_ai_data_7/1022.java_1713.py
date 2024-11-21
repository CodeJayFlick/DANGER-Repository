class DebugHostBaseClassImpl:
    def __init__(self, jna_data):
        self.cleanable = DbgModel.release_when_phantom(self, jna_data)
        self.jna_data = jna_data

    def get_context(self):
        pp_context = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_context(pp_context))
        
        wrap = WrapIDebugHostContext(pp_context.value)
        try:
            return DebugHostContextInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def enumerate_children(self, kind, name):
        ul_kind = kind.ordinal()
        pp_enum = PointerByReference()
        hr = self.jna_data.enumerate_children(ul_kind, name, pp_enum)
        
        if hr == COMUtilsExtra.E_FAIL:
            return None
        COMUtils.check_rc(hr)

        wrap = WrapIDebugHostSymbolEnumerator(pp_enum.value)
        try:
            return DebugHostSymbolEnumeratorInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_symbol_kind(self):
        pul_kind = ULONGByReference()
        COMUtils.check_rc(self.jna_data.get_symbol_kind(pul_kind))
        
        return SymbolKind.values()[pul_kind.value]

    def get_name(self):
        bref = BSTRByReference()
        COMUtils.check_rc(self.jna_data.get_name(bref))

        bstr = bref.value
        model_name = bstr.value
        OleAuto.INSTANCE.SysFreeString(bstr)
        
        return model_name

    def get_type(self):
        pp_type = PointerByReference()
        hr = self.jna_data.get_type(pp_type)

        if hr == COMUtilsExtra.E_FAIL:
            return None
        
        wrap = WrapIDebugHostType1(pp_type.value)
        try:
            return DebugHostTypeInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_containing_module(self):
        pp_type = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_containing_module(pp_type))

        wrap = WrapIDebugHostModule1(pp_type.value)
        try:
            return DebugHostModuleInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_offset(self):
        pp_offset = ULONGLONGByReference()
        COMUtils.check_rc(self.jna_data.get_offset(pp_offset))
        
        return pp_offset.value

    def get_jna_data(self):
        return self.jna_data
