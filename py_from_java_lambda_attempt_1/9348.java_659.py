Here is the equivalent Python code:

```Python
class StringTransferable:
    def __init__(self, data):
        self.data = data.replace('\0', '')

    def get_transfer_data_flavors(self):
        return [DataFlavor('text/plain')]

    def is_data_flavor_supported(self, flavor):
        return isinstance(flavor, str) and flavor == 'text/plain'

    def get_transfer_data(self, flavor):
        if not self.is_data_flavor_supported(flavor):
            raise UnsupportedFlavorException
        return self.data


class DataFlavor:
    @staticmethod
    def string_flavor():
        return 'text/plain'


class UnsupportedFlavorException(Exception):
    pass
```

Please note that Python does not have a direct equivalent to Java's `DataFlavor` and `Transferable`. The above code is an approximation of the original functionality.