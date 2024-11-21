Here is the translation of the Java code into equivalent Python:

```Python
class MockDWARFCompilationUnit:
    def __init__(self, dwarf_program, start_offset, end_offset, length, format, version, abbreviation_offset, pointer_size, comp_unit_number, language):
        self.mock_entries = []
        self.comp_unit_die = None

        super().__init__(dwarf_program, start_offset, end_offset, length, format, version, abbreviation_offset, pointer_size, comp_unit_number)

        compile_unit = DWARFCompileUnit("Mock Comp Unit", "Mock Comp Unit Producer", "Mock Comp Unit Dir", 0, 0, language)
        self.set_compile_unit(compile_unit)
        self.comp_unit_die = DIECreator(DWARFTag.DW_TAG_COMPILE_UNIT).add_string(DWARFAttribute.DW_AT_NAME, f"MockCompUnit{comp_unit_number}").create(self)

    def read_dies(self, dies):
        for die in self.mock_entries:
            dies.append(die)

    @property
    def compile_unit_die(self):
        return self.comp_unit_die

    def add_mock_entry(self, die):
        self.mock_entries.append(die)

    @property
    def mock_entry_count(self):
        return len(self.mock_entries)
```

Note that Python does not have direct equivalent of Java's `List` and other utility classes. Instead, you can use built-in list or dictionary to achieve similar functionality. Also, the concept of constructor (`__init__`) is different in Python compared to Java.