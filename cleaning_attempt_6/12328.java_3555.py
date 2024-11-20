class ImageBaseOffset64DataType:
    def __init__(self):
        self.datatype = QWordDataType.dataType

    @classmethod
    def put(cls, name: str) -> None:
        ClassTranslator.put("ghidra.program.model.data.ImageBaseOffset64", cls.__name__)

    def get_scalar_datatype(self) -> 'QWordDataType':
        return self.datatype

    def clone(self, dtm: 'DataTypeManager') -> 'ImageBaseOffset64DataType':
        if dtm == self.get_data_type_manager():
            return self
        else:
            return ImageBaseOffset64DataType(dtm)

class QWordDataType:
    data_type = None  # Assuming this is a class attribute

class DataTypeManager:
    pass  # Assuming this is an abstract base class or interface

# Usage example:

if __name__ == "__main__":
    datatype_manager = DataTypeManager()  # Replace with actual implementation
    image_base_offset64_datatype = ImageBaseOffset64DataType()
    print(image_base_offset64_datatype.get_scalar_datatype())
