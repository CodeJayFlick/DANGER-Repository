class DebugSymbolsInternal:
    _cache = weakref.WeakValueDictionary()

    @classmethod
    def instance_for(cls, symbols):
        return DbgEngUtil.lazy_weak_cache(_cache, symbols)

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgEngUtil.try_preferred_interfaces(DebugSymbolsInternal.__class__, _preferred_symbols_iids, supplier)

    _preferred_symbols_iids = {
        IDebugSymbols5.IID_IDebug_Symbols5: WrapIDebugSymbols5,
        IDebugSymbols4.IID_IDebug_Symbols4: WrapIDebugSymbols4,
        IDebugSymbols3.IID_IDebug_Symbols3: WrapIDebugSymbols3,
        IDebugSymbols2.IID_IDebug_Symbols2: WrapIDebugSymbols2,
        IDebugSymbols.IID_IDebug_Symbols: WrapIDebugSymbols
    }

    def get_module_name(self, which, module):
        # Implement this method

    def get_module_parameters(self, count, start_index):
        # Implement this method


class DbgEngUtil:
    @classmethod
    def lazy_weak_cache(cls, cache, symbols, factory=None):
        if isinstance(symbols, tuple) and len(symbols) == 1 and callable(symbols[0]):
            return symbols[0]()
        elif factory is not None:
            return factory()
        else:
            return cache.get(symbols)
        # Implement this method

    @classmethod
    def try_preferred_interfaces(cls, cls_, preferred_iids, supplier):
        for i in reversed(range(len(preferred_iids))):
            if isinstance(preferred_iids[i], tuple) and len(preferred_iids[i]) == 1:
                return preferred_iids[i][0]()
        # Implement this method


class WrapIDebugSymbols5:
    pass

class WrapIDebugSymbols4:
    pass

class WrapIDebugSymbols3:
    pass

class WrapIDebugSymbols2:
    pass

class WrapIDebugSymbols:
    pass
