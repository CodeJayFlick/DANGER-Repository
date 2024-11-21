import ctypes
from comtypes import HRESULT, ULONG, ULONGLONG, WString, String

class DEBUG_MODULE_AND_ID:
    pass

class DEBUG_SYMBOL_ENTRY:
    pass

class WrapIDebugSymbols3:
    def __init__(self):
        pass

    def __init__(self, pvInstance):
        super().__init__()

    def GetCurrentScopeFrameIndex(self) -> HRESULT:
        return self._invokeHR(0x0001, None)

    def SetCurrentScopeFrameIndex(self, Index: ULONG) -> HRESULT:
        return self._invokeHR(0x0002, Index)

    def GetModuleByModuleNameWide(self, Name: WString, StartIndex: ULONG, ByReference Index: ULONG, 
                                    ByReference Base: ULONGLONG) -> HRESULT:
        return self._invokeHR(0x0003, (Name, StartIndex, Index, Base))

    def GetModuleNameStringWide(self, Which: ULONG, Index: ULONG, Base: ULONGLONG, Buffer: bytes, 
                                 BufferSize: ULONG, ByReference NameSize: ULONG) -> HRESULT:
        return self._invokeHR(0x0004, (Which, Index, Base, Buffer, BufferSize, NameSize))

    def GetSymbolEntriesByName(self, Symbol: str, Flags: ULONG, Ids: list[DEBUG_MODULE_AND_ID], 
                                 IdsCount: ULONG, ByReference Entries: ULONG) -> HRESULT:
        return self._invokeHR(0x0005, (Symbol, Flags, Ids, IdsCount, Entries))

    def GetSymbolEntriesByNameWide(self, Symbol: WString, Flags: ULONG, Ids: list[DEBUG_MODULE_AND_ID], 
                                    IdsCount: ULONG, ByReference Entries: ULONG) -> HRESULT:
        return self._invokeHR(0x0006, (Symbol, Flags, Ids, IdsCount, Entries))

    def GetSymbolEntryInformation(self, Id: DEBUG_MODULE_AND_ID, Info: DEBUG_SYMBOL_ENTRY.ByReference) -> HRESULT:
        return self._invokeHR(0x0007, (Id, Info))

    def GetSymbolEntryString(self, Id: DEBUG_MODULE_AND_ID, Which: ULONG, Buffer: bytes, 
                              BufferSize: ULONG, ByReference StringSize: ULONG) -> HRESULT:
        return self._invokeHR(0x0008, (Id, Which, Buffer, BufferSize, StringSize))

    def GetSymbolEntryStringWide(self, Id: DEBUG_MODULE_AND_ID, Which: ULONG, Buffer: bytes, 
                                  BufferSize: ULONG, ByReference StringSize: ULONG) -> HRESULT:
        return self._invokeHR(0x0009, (Id, Which, Buffer, BufferSize, StringSize))

    def _invokeHR(self, func_id: int, *args):
        # implement the actual invocation of the native function
        pass

class DEBUG_SYMBOL_ENTRY_ByReference(DEBUG_SYMBOL_ENTRY):
    pass

WrapIDebugSymbols3.ByReference = type('ByReference', (WrapIDebugSymbols3,), {'__module__': 'comtypes'})
