class ConstantPoolInterfaceMethodReferenceInfo:
    def __init__(self, reader):
        super().__init__(reader)

    def to_data_type(self) -> dict:
        structure = self.to_data_type()
        try:
            structure["name"] = "CONSTANT_InterfaceMethodref_info"
        except Exception as e:
            raise ValueError(str(e))
        return structure
