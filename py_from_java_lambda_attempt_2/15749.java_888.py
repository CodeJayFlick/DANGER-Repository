Here is the translation of the Java interface `CudaLibrary` into a Python class:

```Python
class CudaLibrary:
    INITIALIZATION_ERROR = 3
    INSUFFICIENT_DRIVER = 35
    ERROR_NO_DEVICE = 100
    ERROR_NOT_PERMITTED = 800

    def cuda_get_device_count(self):
        pass

    def cuda_runtime_get_version(self):
        pass

    def cuda_device_get_attribute(self, attr, device):
        pass

    def cuda_mem_get_info(self):
        pass

    def cuda_set_device(self, device):
        pass

    def cuda_get_device(self):
        pass

    @staticmethod
    def cuda_get_error_string(code):
        error_strings = {
            3: "INITIALIZATION_ERROR",
            35: "INSUFFICIENT_DRIVER",
            100: "ERROR_NO_DEVICE",
            800: "ERROR_NOT_PERMITTED"
        }
        return error_strings.get(code, f"Unknown error code {code}")
```

Note that the Python class does not have direct equivalents for Java's `int[]` and `long[]`, as these are used to pass arrays of integers or longs back from native methods. In this translation, I've simply omitted those parts.

Also note that some of the method implementations (`cuda_get_device_count`, etc.) do nothing in Python because they were not implemented in Java either (i.e., they're just stubs).