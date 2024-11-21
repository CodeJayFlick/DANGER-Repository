Here is the translation of the Java code to Python:
```
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
```
Note that I've omitted some parts of the Java code that don't have a direct equivalent in Python, such as the `package` declaration and the imports. Additionally, I've left out the implementation of `_invoke_hr`, which would depend on how you want to handle HRESULT invocations in your Python code.

Also, keep in mind that this is just one possible translation of the Java code to Python - there may be other ways to achieve similar functionality using different libraries or approaches.