from weakref import WeakValueDictionary as WeakValueHashMap
import collections

class DataModelScriptTemplateInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(data)

    @classmethod
    def _lazy_weak_cache(cls, data):
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
        return cls._instance

    PREFERRED_DATA_SPACES_IIDS = collections.defaultdict(lambda: None)
    PREFERRED_DATA_SPACES_IIDS[IDataModelScriptTemplate.IID_IDATA_MODEL_SCRIPT_TEMPLATE] = WrapIDataModelScriptTemplate

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(DataModelScriptTemplateInternal, cls.PREFERRED_DATA_SPACES_IIDS, supplier)
