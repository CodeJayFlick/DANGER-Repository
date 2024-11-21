from weakref import WeakValueDictionary as WeakHashMap
import collections

class DebugDataSpacesInternal:
    _cache = WeakHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, data):
        if isinstance(data, WrapIDebugDataSpaces1):
            return cls.new_instance(DebugDataSpacesImpl1)
        elif isinstance(data, WrapIDebugDataSpaces2):
            return cls.new_instance(DebugDataSpacesImpl2)
        elif isinstance(data, WrapIDebugDataSpaces3):
            return cls.new_instance(DebugDataSpacesImpl3)
        elif isinstance(data, WrapIDebugDataSpaces4):
            return cls.new_instance(DebugDataSpacesImpl4)

    @classmethod
    def new_instance(cls, impl_class):
        if not hasattr(cls, '_instance'):
            cls._instance = impl_class()
        return cls._instance

    _preferred_data_spaces_iids = collections.defaultdict(dict)
    _preferred_data_spaces_iids[IDebugDataSpaces4.IID_IDBUG_DATA_SPACES4] = WrapIDebugDataSpaces4
    _preferred_data_spaces_iids[IDebugDataSpaces3.IID_IDBUG_DATA_SPACES3] = WrapIDebugDataSpaces3
    _preferred_data_spaces_iids[IDebugDataSpaces2.IID_IDBUG_DATA_SPACES2] = WrapIDebugDataSpaces2
    _preferred_data_spaces_iids[IDebugDataSpaces.IID_IDBUG_DATA_SPACES] = WrapIDebugDataSpaces

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgEngUtil.try_preferred_interfaces(DebugDataSpacesInternal.__class__, cls._preferred_data_spaces_iids, supplier)
