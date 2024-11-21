from weakref import WeakValueDictionary as WeakValueHashMap
import immutable

class DynamicConceptProviderConceptInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(_cache, data, lambda: cls())

    PREFERRED_DATA_SPACES_IIDS_BUILDER = immutable.Map.builder()
    PREFERRED_DATA_SPACES_IIDS = PREFERRED_DATA_SPACES_IIDS_BUILDER \
                                    .put(IDynamicConceptProviderConcept.IID_IDYNAMIC_CONCEPT_PROVIDER_CONCEPT,
                                         WrapIDynamicConceptProviderConcept) \
                                    .build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(DynamicConceptProviderConceptInternal, PREFERRED_DATA_SPACES_IIDS, supplier)
