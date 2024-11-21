import ctypes

class WrapIDebugHostSymbol1:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def CompareAgainst(self, p_comparison_symbol, comparison_flags, p_matches):
        return self._invoke_hr(0x01, self.get_pointer(), p_comparison_symbol,
                                comparison_flags, p_matches)

class ByReference(WrapIDebugHostSymbol1):
    pass

def _invoke_hr(index, instance, *args):
    # implement this function to handle the HR (HRESULT) invocation
    pass

WrapIDebugHostSymbol1.VTIndices = {
    0x01: "COMPARE_AGAINST"
}
