Here is the translation of the given Java code into equivalent Python:

```Python
class OatDexFile_Marshmallow(OatDexFile_Lollipop):
    def __init__(self, reader):
        super().__init__(reader)

    def to_data_type(self):
        data_type = super().to_data_type()
        try:
            data_type.name = f"{OatDexFile_Marshmallow.__name__}_{len(oat_class_offsets_pointer_)}"
        except Exception as e:
            # ignore
            pass
        return data_type

# Note: oat_class_offsets_pointer_ is not defined in the given Java code, so it's assumed to be a class variable.
oat_class_offsets_pointer_ = []
```

This Python translation maintains the same structure and functionality as the original Java code. The `OatDexFile_Marshmallow` class inherits from `OatDexFile_Lollipop`, and its constructor (`__init__`) calls the parent's constructor with a given reader object.

The `to_data_type` method is overridden to modify the name of the data type based on some conditions.