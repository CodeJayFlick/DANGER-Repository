Here is the translation of the given Java code into Python:

```Python
import os
from typing import Set

class Activator:
    _close_set: set = set()
    _plugin_id = "GhidraDev"
    _ghidra_install_dir_property = "ghidra.install.dir"

    @classmethod
    def get_default(cls) -> 'Activator':
        return cls._plugin

    def __init__(self):
        self._plugin = None

    def register_closeable(self, closeable: object) -> None:
        if not isinstance(closeable, object):
            raise TypeError("Closeable must be an instance of object")
        self._close_set.add(closeable)

    def unregister_closeable(self, closeable: object) -> None:
        try:
            self._close_set.remove(closeable)
        except KeyError:
            pass

    @property
    def ghidra_install_dir_property(self):
        return self._ghidra_install_dir_property

    @classmethod
    def get_ghidra_install_dir(cls) -> str | None:
        property_value = os.environ.get(cls._ghidra_install_dir_property)
        if property_value is not None and len(property_value.strip()) > 0:
            return property_value
        else:
            return None

    @classmethod
    def is_launched_by_ghidra(cls) -> bool:
        return cls.get_ghidra_install_dir() is not None

    def start(self, context: object) -> None:
        self._plugin = self
        print(f"Starting {self._plugin_id} plugin")

    def stop(self, context: object) -> None:
        self._plugin = None
        super().stop(context)
        print(f"Stopping {self._plugin_id} plugin")
        
        # Close registered items
        for closeable in list(self._close_set):
            if closeable is not None:
                try:
                    closeable.close()
                except Exception as e:
                    print(f"Failed to close {closeable}")
        self._close_set.clear()

if __name__ == "__main__":
    activator = Activator()
```

Please note that Python does not have direct equivalent of Java's `BundleContext` and `AbstractUIPlugin`. The code above is a simplified translation, it may need further modifications based on the actual requirements.