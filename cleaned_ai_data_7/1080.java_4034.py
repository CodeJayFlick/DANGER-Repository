from weakref import WeakValueDictionary as Map
import functools

class ModelMethodInternal:
    _cache = Map()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, cache, data, factory):
        if not isinstance(cache, dict):
            cache = {}
        try:
            result = cache[data]
        except KeyError:
            result = cache.setdefault(data, factory())
        return result

    PREFERRED_DATA_SPACES_IIDS = {}

    @classmethod
    def _build_preferred_data_spaces_iids(cls):
        preferred_data_spaces_iids_builder = {}
        preferred_data_spaces_iids_builder[ModelMethod.IID_MODEL_METHOD] = type(WrapIModelMethod)
        return dict(preferred_data_spaces_iids_builder)

    PREFERRED_DATA_SPACES_IIDS = _build_preferred_data_spaces_iids()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(ModelMethodInternal.__class__, cls.PREFERRED_DATA_SPACES_IIDS, supplier)
