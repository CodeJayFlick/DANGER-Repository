Here is the translation of the given Java code into equivalent Python:

```Python
class IDebugHostModule2:
    IID_IDEBUG_HOST_MODULE2 = "B51887E8-BCD0-4e8f-A8C7-434398B78C37"

    class VTIndices2:
        FIND_CONTAINING_SYMBOL_BY_RVA = 1

        def __init__(self):
            self.start = IDebugHostModule2.VTIndices1.follow()

        def get_index(self):
            return self.ordinal() + self.start


class HRESULT(int): pass
class ULONGLONG(int): pass
class ULONGLONGByReference(ULONGLONG): pass
class PointerByReference(object): pass

def find_containing_symbol_by_rva(rva, symbol, offset):
    # Implement the logic for FindContainingSymbolByRVA method here.
    return 0


# Usage:
module = IDebugHostModule2()
rva = ULONGLONG(123)
symbol = None
offset = ULONGLONG(456)

result = module.find_containing_symbol_by_rva(rva, symbol, offset)
print(result)