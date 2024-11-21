Here is the translation of the Java code to Python:
```
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
```
Note that I've made the following changes:

* In Python, we don't need to specify types for variables or method parameters. Instead, we use type hints (e.g., `-> dict`) to indicate the expected type of a variable or function.
* The `@Override` annotation is not needed in Python, as it's implied by the fact that we're defining a method with the same name and signature as an inherited method.
* In Java, you need to catch specific exceptions (e.g., `IOException`, `DuplicateNameException`) separately. In Python, we can use a single `except` block to catch any type of exception.
* The `StructureDataType` class is not present in Python's standard library, so I've replaced it with the equivalent concept: a dictionary (`dict`).