Here is a translation of the Java code into equivalent Python code:

```Python
class DebugHostModuleImpl2:
    def __init__(self, jna_data):
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def find_containing_symbol_by_rva(self, rva):
        ul_rva = ULONGLONG(rva)
        pp_symbol = PointerByReference()
        pul_offset = ULONGLONGByReference()
        COMUtils.check_rc(self.jna_data.find_containing_symbol_by_rva(ul_rva, pp_symbol, pul_offset))

        self.offset = pul_offset.get_value().value

        wrap = WrapIDebugHostSymbol1(pp_symbol.get_value())
        try:
            return DebugHostSymbolInternal.try_preferred_interfaces(wrap.query_interface)
        finally:
            wrap.release()

    def get_offset(self):
        return self.offset
```

Note that Python does not have direct equivalents for Java's `ULONGLONG`, `PointerByReference` and other JNA-specific classes. These types are used to interact with native code, which is typically done using libraries like ctypes or cffi in Python.

In this translation, I've assumed that these types can be replaced by equivalent Python constructs (e.g., integers for the ULONGLONG type).