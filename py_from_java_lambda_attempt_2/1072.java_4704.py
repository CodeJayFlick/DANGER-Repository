Here is a translation of the Java code into equivalent Python code:

```Python
import ctypes

class KeyStoreImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # No direct equivalent in Python
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def get_key(self, key: str) -> 'ModelObject':
        pp_object = ctypes.POINTER(ctypes.c_void_p)()
        pp_metadata = ctypes.POINTER(ctypes.c_void_p)()
        result = self.jna_data.get_key(key.encode(), byref(pp_object), byref(pp_metadata))
        return ModelObjectImpl.get_object_with_metadata(pp_object, pp_metadata)

    def set_key(self, key: str, object: 'ModelObject', metadata: 'KeyStore'):
        p_object = object.get_pointer()
        p_metadata = metadata.get_pointer()
        self.jna_data.set_key(key.encode(), p_object, p_metadata)

    def get_key_value(self, key: str) -> 'ModelObject':
        pp_object = ctypes.POINTER(ctypes.c_void_p)()
        pp_metadata = ctypes.POINTER(ctypes.c_void_p)()
        result = self.jna_data.get_key_value(key.encode(), byref(pp_object), byref(pp_metadata))
        return ModelObjectImpl.get_object_with_metadata(pp_object, pp_metadata)

    def set_key_value(self, key: str, object: 'ModelObject'):
        p_object = object.get_pointer()
        self.jna_data.set_key_value(key.encode(), p_object)

    def clear_keys(self):
        self.jna_data.clear_keys()

class ModelObjectImpl:
    @staticmethod
    def get_object_with_metadata(pp_object, pp_metadata):
        # This method is not provided in the original Java code.
        pass

def byref(ptr: ctypes.POINTER) -> 'ctypes.POINTER':
    return ptr
```

Note that Python does not have direct equivalents for some of the Java concepts used here (e.g., `OpaqueCleanable`, `IKeyStore`), so they were removed or replaced with equivalent constructs.