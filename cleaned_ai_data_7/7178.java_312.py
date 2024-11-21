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
