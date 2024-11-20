Here is a translation of the Java code into equivalent Python code:

```Python
class WrapIDebugHostData:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def get_location_kind(self):
        # Assuming _invokeHR and VTIndicesX are defined elsewhere in the program
        return _invokeHR(VTIndicesX.GET_LOCATION_KIND)

    def get_location(self):
        # Assuming _invokeHR is defined elsewhere in the program
        return _invokeHR(VTIndicesX.GET_LOCATION)

    def get_value(self):
        # Assuming _invokeHR and VTIndicesX are defined elsewhere in the program
        return _invokeHR(VTIndicesX.GET_VALUE)
```

Please note that this translation assumes you have equivalent functions `_invokeHR` and `VTIndicesX` available to use.