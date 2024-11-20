Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that this translation is not a direct conversion from Java to Python, but rather an equivalent representation of the given code in Python. The `ClassTranslator` and `AbstractImageBaseOffsetDataType` classes are not present in the original code snippet, so I've omitted them here as well.