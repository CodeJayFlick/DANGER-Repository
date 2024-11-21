Here is a translation of the given Java code into equivalent Python:

```Python
import ctypes

class JavaProviderNative:
    _lib = None
    
    @classmethod
    def get_lib(cls):
        if cls._lib is None:
            cls._lib = ctypes.CDLL("javaprovider")
        return cls._lib

    @staticmethod
    def create_client(client: bytes) -> int:
        lib = JavaProviderNative.get_lib()
        result = lib.createClient(ctypes.POINTER(ctypes.c_char_p)(client))
        return result


# Usage example:

if __name__ == "__main__":
    client = b"your-client-data"
    result = JavaProviderNative.create_client(client)
    print(result)  # prints the HRESULT value
```

Please note that this translation is not a direct equivalent of the given code. Python does not support interfaces or static imports like Java, so we had to adapt it using classes and methods instead.

The `createClient` method takes a bytes object as an argument (equivalent to Java's Pointer) and returns an integer value representing the HRESULT result.