Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractLocalOrParameterStoredInRegisterMsSymbol:
    def __init__(self):
        self.type_record_number = None
        self.attributes = None
        self.register_index = 0
        self.register_name = ""
        self.name = ""

    @classmethod
    def from_pdb(cls, pdb, reader, str_type):
        instance = cls()
        super().__init__()
        instance.type_record_number = RecordNumber.parse(pdb, reader, "TYPE", 32)
        instance.attributes = LocalVariableAttributes.from_pdb(pdb, reader)
        instance.register_index = reader.read_unsigned_short_val()
        instance.register_name = RegisterName(reader, instance.register_index).to_string()
        instance.name = reader.read_string(pdb, str_type)
        return instance

    def emit(self):
        my_builder = StringBuilder()
        my_builder.append(str(instance.type_record_number))
        self.attributes.emit(my_builder)
        builder = StringBuilder(f"{self.get_symbol_type_name()}: {instance.register_name}, {my_builder.toString()}, {self.name}")
```

Please note that Python does not have direct equivalent of Java's abstract class, interfaces or generic types. Also, the `emit` method is assumed to be a part of some larger class and hence it uses an instance variable (`builder`) which might need adjustment based on your actual use case.

Also, this translation assumes that you are using a Python library like `pypdbreader` for parsing PDB files (similarly as Java's `PdbByteReader`).