Here is the translation of the given Java code into equivalent Python:

```Python
from weakref import WeakValueDictionary as WeakValueHashMap
import immutable as ImmutableMap

class DebugHostSymbolEnumeratorInternal:
    CACHE = WeakValueHashMap()

    @classmethod
    def instance_for(cls, data):
        return DbgModelUtil.lazy_weak_cache(DebugHostSymbolEnumeratorInternal.CACHE, data, lambda: cls())

    PREFERRED_DATA_SPACES_IIDS_BUILDER = ImmutableMap.builder()
    PREFERRED_DATA_SPACES_IIDS = PREFERRED_DATA_SPACES_IIDS_BUILDER \
                                    .put({IDebugHostSymbolEnumerator.IID_IDEBUG_HOST_SYMBOL_ENUMERATOR}, WrapIDebugHostSymbolEnumerator) \
                                    .build()

    @classmethod
    def try_preferred_interfaces(cls, supplier):
        return DbgModelUtil.try_preferred_interfaces(DebugHostSymbolEnumeratorInternal, PREFERRED_DATA_SPACES_IIDS, supplier)
```

Please note that Python does not have direct equivalent of Java's `package`, `import java.util.Map;` and similar statements. Also, the concept of interfaces in Python is different from Java. In Python, you can achieve something similar to interface using abstract base classes (ABCs) or duck typing.

In this translation, I've used a class as an example for what would be equivalent to an interface in Java.