from weakref import WeakValueDictionary as CacheType
import immutable as ImmutableMap

class EquatableConceptInternal:
    CACHE = CacheType()

    @classmethod
    def instance_for(cls, data):
        return cls.lazy_weak_cache(cls.CACHE, data)

    PREFERRED_DATA_SPACES_IIDS_BUILDER = ImmutableMap.builder()
    PREFERRED_DATA_SPACES_IIDS = PREFERRED_DATA_SPACES_IIDS_BUILDER \
                                    .put(IEquatableConcept.IID_IEQUATABLE_CONCEPT,
                                         WrapIEquatableConcept.__class__) \
                                    .build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(EquatableConceptInternal, 
                                                      cls.PREFERRED_DATA_SPACES_IIDS, 
                                                      supplier)
