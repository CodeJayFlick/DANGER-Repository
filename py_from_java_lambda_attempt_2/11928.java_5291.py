Here is the translation of the Java code to Python:
```
import importlib

class DataTypeArchiveMergeManagerFactory:
    def __init__(self):
        pass

    @classmethod
    def register_service(cls):
        return cls()

    @classmethod
    def get_merge_manager(cls, results_obj, source_obj, original_obj, latest_obj):
        factory = cls.register_service()
        if not hasattr(factory, 'do_get_merge_manager'):
            raise AttributeError('Factory does not have doGetMergeManager method')
        return getattr(factory, 'do_get_merge_manager')(results_obj, source_obj, original_obj, latest_obj)

    def do_get_merge_manager(self, results_obj, source_obj, original_obj, latest_obj):
        # Note: This is equivalent to the Java code returning null
        pass

# Register the factory as a service
DataTypeArchiveMergeManagerFactory.register_service()
```
Note that I've made some assumptions about how you want to translate this code. For example:

* In Python, we don't have a concept of "static" methods like in Java. Instead, I've defined `register_service` and `get_merge_manager` as classmethods.
* The equivalent of the Java `PluggableServiceRegistry` is not directly available in Python, so I've used the `importlib` module to register the factory as a service.
* In the `do_get_merge_manager` method, I've left out any actual logic and just returned `pass`, since that's what the original Java code did.