import ctypes.util
from com.sun.jna import Pointer, PointerByReference
from com.sun.jna.platform.win32.COM import COMUtils
from agent.dbgmodel.impl.dbgmodel.debughost import DebugHostInternal
from agent.dbgmodel.impl.dbgmodel.main import KeyStore

class DebugHostImpl(DebugHostInternal):
    def __init__(self, jna_data):
        self.cleanable = DbgModel.release_when_phantom(self, jna_data)
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def get_host_defined_interface(self):
        pp_host_unk = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_host_defined_interface(pp_host_unk))
        wrap = WrapIUnknownEx(pp_host_unk.value)
        try:
            return UnknownExInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_current_context(self):
        pp_context = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_current_context(pp_context))
        wrap = WrapIDebugHostContext(pp_context.value)
        try:
            return DebugHostContextInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_default_metadata(self):
        pp_default_metadata_store = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_default_metadata(pp_default_metadata_store))
        wrap = WrapIKeyStore(pp_default_metadata_store.value)
        try:
            return KeyStoreInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def as_memory(self):
        return DebugHostMemoryInternal.try_preferred_interfaces(self.jna_data.query_interface())

    def as_symbols(self):
        return DebugHostSymbolsInternal.try_preferred_interfaces(self.jna_data.query_interface())

    def as_script_host(self):
        return DebugHostScriptHostInternal.try_preferred_interfaces(self.jna_data.query_interface())

    def as_evaluator(self):
        return (DebugHostEvaluator2) DebugHostEvaluatorInternal.try_preferred_interfaces(self.jna_data.query_interface())
