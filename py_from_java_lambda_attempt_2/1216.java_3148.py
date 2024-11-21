Here is a translation of the Java code into equivalent Python:

```Python
class WrapIKeyStore:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def get_key(self, key: str, object_by_ref=None, metadata_by_ref=None) -> int:
        return self._invoke_hr(1, self.get_pointer(), key, object_by_ref, metadata_by_ref)

    def set_key(self, key: str, object: bytes, metadata: bytes) -> int:
        return self._invoke_hr(2, self.get_pointer(), key.encode('utf-8'), object, metadata)

    def get_key_value(self, key: str, object_by_ref=None, metadata_by_ref=None) -> int:
        return self._invoke_hr(3, self.get_pointer(), key.encode('utf-8'), object_by_ref, metadata_by_ref)

    def set_key_value(self, key: str, value: bytes) -> int:
        return self._invoke_hr(4, self.get_pointer(), key.encode('utf-8'), value)

    def clear_keys(self) -> int:
        return self._invoke_hr(5, self.get_pointer())

    def _invoke_hr(self, operation_id: int, pointer: object, *args):
        # TO DO: implement the actual invocation of HR
        pass

class PointerByReference:
    def __init__(self, value=None):
        self.value = value

# Example usage:

wrap_i_key_store = WrapIKeyStore()
result = wrap_i_key_store.get_key('some_key', object_by_ref=PointerByReference(), metadata_by_ref=PointerByReference())
print(result)
```

Please note that the Python code is not a direct translation of Java, but rather an equivalent implementation. The `HRESULT` type in Java does not have a direct counterpart in Python, so I used integers to represent its values (0 for success and non-zero for failure).