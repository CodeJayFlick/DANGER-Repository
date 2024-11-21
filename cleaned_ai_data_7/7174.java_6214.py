class OatDexFile_Android10:
    def __init__(self, reader, vdex_header):
        super().__init__(reader, vdex_header)

    def to_data_type(self) -> object:
        data_type = super().to_data_type()
        try:
            class_name = type(self).__name__
            data_type.name = class_name
        except Exception as e:
            pass  # ignore the exception

# Example usage:

class BinaryReader: ...  # implement this class if needed
vdex_header = VdexHeader()  # implement this class if needed

reader = BinaryReader()
oat_file_android10 = OatDexFile_Android10(reader, vdex_header)
data_type = oat_file_android10.to_data_type()

