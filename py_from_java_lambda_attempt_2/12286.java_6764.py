Here is the translation of the Java code into Python:

```Python
class DataTypeTransferable:
    local_data_type_flavor = None
    local_builtin_data_type_flavor = None
    
    def __init__(self, dt):
        self.data_type = dt
        
    @property
    def flavors(self):
        return [self.local_data_type_flavor, self.local_builtin_data_type_flavor]
    
    @property
    def flavor_list(self):
        return self.flavors

    def get_transfer_data_flavors(self):
        return self.flavors
    
    def is_data_flavor_supported(self, f):
        return f in self.flavor_list
    
    def get_transfer_data(self, f):
        if f == self.local_data_type_flavor or f == self.local_builtin_data_type_flavor:
            return self.data_type
        else:
            raise UnsupportedFlavorException(f)
    
    def __str__(self):
        return "DataTypeTransferable"
```

Note that Python does not have direct equivalents for Java's `DataFlavor` and `ClipboardOwner`, so I did not include those in the translation.