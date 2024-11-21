Here is the translation of the Java code into Python:

```Python
import threading
from collections import defaultdict

class BundleMap:
    def __init__(self):
        self._lock = threading.Lock()
        self.bundles_by_file = {}
        self.bundles_by_location = {}

    def add(self, bundle):
        with self._lock:
            self.bundles_by_file[bundle.file] = bundle
            self.bundles_by_location[bundle.location_identifier] = bundle

    def add_all(self, bundles):
        with self._lock:
            for bundle in bundles:
                self.add(bundle)

    def remove(self, bundle):
        with self._lock:
            if bundle.file in self.bundles_by_file:
                del self.bundles_by_file[bundle.file]
            if bundle.location_identifier in self.bundles_by_location:
                del self.bundles_by_location[bundle.location_identifier]

    def remove_all(self, bundles):
        with self._lock:
            for bundle in bundles:
                self.remove(bundle)

    def get_bundle_at_location(self, location):
        with self._lock:
            return self.bundles_by_location.get(location)

    def get(self, bundle_file):
        with self._lock:
            return self.bundles_by_file.get(bundle_file)

    def compute_all_if_absent(self, bundle_files, ctor):
        with self._lock:
            new_bundle_files = set(bundle_files) - set(self.bundles_by_file.keys())
            new_bundles = [ctor(file) for file in new_bundle_files]
            self.add_all(new_bundles)
            return new_bundles

    def get_ghidra_bundles(self):
        with self._lock:
            return list(self.bundles_by_file.values())

    def get_bundle_files(self):
        with self._lock:
            return list(self.bundles_by_file.keys())
```

Note that Python does not have a direct equivalent to Java's `ReadWriteLock` and `ReentrantReadWriteLock`. Instead, we use the built-in `threading.Lock()` class which can be used as a read-write lock.