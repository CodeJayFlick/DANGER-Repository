from weakref import WeakValueDictionary as WeakValueHashMap
import immutable

class StringDisplayableConceptInternal:
    _cache = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return cls._lazy_weak_cache(_cache, data)

    PREFERRED_DATA_SPACES_IIDS = immutable.Map.builder()
    .put(REFIID(IStringDisplayableConcept.IID_ISTRING_DISPLAYABLE_CONCEPT), WrapIStringDisplayableConcept)
    ._build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return cls._try_preferred_interfaces(StringDisplayableConceptInternal.__class__, PREFERRED_DATA_SPACES_IIDS, supplier)

# Helper functions

def _lazy_weak_cache(cache, data):
    # Implement the lazy weak cache logic here
    pass

def _try_preferred_interfaces(cls, preferred_data_spaces_iids, supplier):
    # Implement the try preferred interfaces logic here
    pass


class REFIID:
    @staticmethod
    def IID_ISTRING_DISPLAYABLE_CONCEPT():
        return "IStringDisplayableConcept"


class WrapIStringDisplayableConcept:
    pass

class IStringDisplayableConcept:
    IID_ISTRING_DISPLAYABLE_CONCEPT = None  # Replace with actual value


# You can use the above classes and functions as needed
