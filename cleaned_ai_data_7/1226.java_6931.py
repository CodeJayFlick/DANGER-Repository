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
