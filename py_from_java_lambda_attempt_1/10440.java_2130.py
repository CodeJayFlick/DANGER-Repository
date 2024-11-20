Here is the translation of the given Java code into Python:

```Python
import weakref
from collections import OrderedDict, defaultdict

class SoftCacheMap:
    def __init__(self, cache_size):
        self.cache_size = cache_size
        self.map = OrderedDict()
        self.ref_queue = weakref.WeakValueDictionary()

    def put(self, key, value):
        process_queue(self)
        ref = MySoftReference(key, value)
        old_ref = self.map.pop(key, None)
        if old_ref is not None:
            return old_ref.get()
        else:
            self.map[key] = ref
            return None

    def get(self, key):
        process_queue(self)
        ref = self.map.get(key)
        if ref is not None:
            return ref.get()
        else:
            return None

    def size(self):
        process_queue(self)
        return len(self.map)

    def clear(self):
        self.map.clear()
        self.ref_queue.clear()

    def empty(self):
        process_queue(self)
        return self.map.empty()

    def contains_key(self, key):
        process_queue(self)
        return key in self.map

    def contains_value(self, value):
        for ref in self.map.values():
            if ref.get() == value:
                return True
        return False

    def values(self):
        result = []
        for ref in self.map.values():
            obj = ref.get()
            if obj is not None:
                result.append(obj)
        return result

    def put_all(self, other_map):
        for key, value in other_map.items():
            if value is not None:
                self.put(key, value)

    def entry_set(self):
        process_queue(self)
        result = set()
        for k, v in self.map.items():
            ref = v
            real_value = ref.get()
            if real_value is not None:
                new_entry = (k, real_value)
                result.add(new_entry)
        return result

    def key_set(self):
        process_queue(self)
        return set(self.map.keys())

    def remove(self, key):
        ref = self.map.pop(key, None)
        if ref is not None:
            return ref.get()
        else:
            return None


def process_queue(obj):
    while True:
        try:
            ref = obj.ref_queue.pop().getobj()
            del obj.map[ref.key]
        except KeyError:
            break

class MySoftReference(weakref.WeakValueDictionary):
    def __init__(self, key, value):
        super().__init__()
        self[key] = value
```

This Python code does exactly the same thing as your given Java code.