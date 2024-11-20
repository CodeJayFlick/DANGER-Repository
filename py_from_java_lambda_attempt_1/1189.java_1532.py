Here is a translation of the given Java code into equivalent Python:

```Python
class WrapIDebugHostModule1:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def get_image_name(self, allow_path=False, image_name=None):
        # Assuming _invokeHR is a function that takes the necessary parameters
        return _invokeHR(VTIndices1.GET_IMAGE_NAME, self.get_pointer(), allow_path, image_name)

    def get_base_location(self):
        # Assuming _invokeHR is a function that takes the necessary parameters
        return _invokeHR(VTIndices1.GET_BASE_LOCATION, self.get_pointer())

    def get_version(self):
        file_version = None
        product_version = None
        # Assuming _invokeHR is a function that takes the necessary parameters
        return _invokeHR(VTIndices1.GET_VERSION, self.get_pointer(), file_version, product_version)

    def find_type_by_name(self, type_name):
        type_ = None
        # Assuming _invokeHR is a function that takes the necessary parameters
        return _invokeHR(VTIndices1.FIND_TYPE_BY_NAME, self.get_pointer(), type_name, type_)

    def find_symbol_by_rva(self, rva):
        symbol = None
        # Assuming _invokeHR is a function that takes the necessary parameters
        return _invokeHR(VTIndices1.FIND_SYMBOL_BY_RVA, self.get_pointer(), rva, symbol)

    def find_symbol_by_name(self, symbol_name):
        symbol = None
        # Assuming _invokeHR is a function that takes the necessary parameters
        return _invokeHR(VTIndices1.FIND_SYMBOL_BY_NAME, self.get_pointer(), symbol_name, symbol)
```

Please note that this translation assumes you have defined `_invokeHR` and `VTIndices1` elsewhere in your code.