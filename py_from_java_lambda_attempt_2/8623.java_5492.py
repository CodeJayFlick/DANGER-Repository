Here is the translation of the given Java code into Python:

```Python
class DummyPdb700:
    def __init__(self, tpi_index_min: int, tpi_index_max_exclusive: int, ipi_index_min: int, ipi_index_max_exclusive: int) -> None:
        super().__init__(None, PdbReaderOptions())
        self.type_program_interface = DummyTypeProgramInterface800(self, tpi_index_min, tpi_index_max_exclusive)
        self.debug_info = DummyDebugInfoNew(self)
        self.has_id_stream = True
        self.item_program_interface = DummyTypeProgramInterface800(self, ipi_index_min, ipi_index_max_exclusive)
        self.name_table.for_testing_only_add_offset_name_pair(1, "NameTableTestString")

    def set_type_record(self, record_number: int, type_: AbstractMsType) -> bool:
        return self.type_program_interface.set_record(record_number, type_)

    def add_type_record(self, type_: AbstractMsType) -> int:
        return self.type_program_interface.add_record(type_)

    def set_item_record(self, record_number: int, type_: AbstractMsType) -> bool:
        return self.item_program_interface.set_record(record_number, type_)

    def add_item_record(self, type_: AbstractMsType) -> int:
        return self.item_program_interface.add_record(type_)
```

Note that this is a direct translation of the Java code into Python. Some differences between the two languages may be noticeable:

- In Python, we don't need to specify types for variables or method parameters like in Java.
- The `throws` keyword used in Java methods does not have an equivalent in Python. Instead, you can use exceptions and handle them accordingly.
- The constructor of a class is defined using the `__init__` method instead of the `public DummyPdb700()` declaration in Java.

Also note that this code assumes that there are classes like `PdbReaderOptions`, `DummyTypeProgramInterface800`, `DummyDebugInfoNew`, and `AbstractMsType` which have not been provided.