Here is the translation of the Java interface `IDebugHostExtensability` into a Python class:

```Python
import ctypes

class IDebugHostExtensability:
    IID_IDDEBUG_HOST_EXTENSABILITY = "3C2B24E1-11D0-4f86-8AE5-4DF166F73253"

    VTIndices = ["CREATE_FUNCTION_ALIAS", "DESTROY_FUNCTION_ALIAS"]

    def __init__(self):
        self._vt_indices = {"CREATE_FUNCTION_ALIAS": 0, "DESTROY_FUNCTION_ALIAS": 1}

    def create_function_alias(self, alias_name: str, function_object) -> int:
        # Implement the CreateFunctionAlias method
        pass

    def destroy_function_alias(self, alias_name: str) -> int:
        # Implement the DestroyFunctionAlias method
        pass


class HRESULT(int):
    pass


def main():
    extensability = IDebugHostExtensability()
    print(extensability.IID_IDDEBUG_HOST_EXTENSABILITY)
    for vt_index in extensability.VTIndices:
        print(vt_index)


if __name__ == "__main__":
    main()

```

Note that the `HRESULT` class is simply a wrapper around Python's built-in integer type, and it does not implement any of the actual functionality from the Java interface.