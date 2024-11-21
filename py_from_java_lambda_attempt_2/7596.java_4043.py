Here is the translation of the Java code into Python:

```Python
class LibraryRecord:
    def __init__(self, record):
        if not record:
            raise ValueError("null record")
        self.record = record

    @property
    def library_id(self):
        return self.record.key

    @property
    def library_family_name(self):
        return self.record[LIBRARY_FAMILY_NAME_COL]

    @property
    def library_version(self):
        return self.record[LIBRARY_VERSION_COL]

    @property
    def library_variant(self):
        return self.record[LIBRARY_VARIANT_COL]

    @property
    def ghidra_version(self):
        return self.record[GHIDRA_VERSION_COL]

    @property
    def ghidra_language_id(self):
        return LanguageID(self.record[GHIDRA_LANGUAGE_ID_COL])

    @property
    def ghidra_language_version(self):
        return self.record[GHIDRA_LANGUAGE_VERSION_COL]

    @property
    def ghidra_language_minor_version(self):
        return self.record[GHIDRA_LANGUAGE_MINOR_VERSION_COL]

    @property
    def ghidra_compiler_spec_id(self):
        return CompilerSpecID(self.record[GHIDRA_COMPILER_SPEC_ID_COL])

    def __str__(self):
        return f"{self.library_family_name} {self.library_version} {self.library_variant}"

class LanguageID:
    def __init__(self, language_id):
        self.language_id = language_id

    @property
    def value(self):
        return self.language_id


class CompilerSpecID:
    def __init__(self, compiler_spec_id):
        self.compiler_spec_id = compiler_spec_id

    @property
    def value(self):
        return self.compiler_spec_id
```

Note: I've used Python's property decorator to create getter methods for the attributes. This is equivalent to Java's getters and setters.