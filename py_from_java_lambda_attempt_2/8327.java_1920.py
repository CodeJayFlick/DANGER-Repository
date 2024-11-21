Here is the translation of the given Java code into Python:

```Python
class AbstractAliasMsType:
    def __init__(self, pdb, reader, str_type):
        super().__init__()
        self._underlying_record_number = RecordNumber.parse(pdb, reader, 'TYPE', 32)
        self.name = reader.parse_string(pdb, str_type)

    @property
    def underlying_record_number(self):
        return self._underlying_record_number

    @property
    def name(self):
        return self.name

    def emit(self, builder, bind):
        # No API for this. Just outputting something that might be useful.
        # At this time, not doing anything with bind here; don't think it is warranted.
        builder.append(pdb.get_type_record(self._underlying_record_number))
        builder.append(" ")
        builder.append(self.name)

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement this method as per your requirement

class PdbByteReader:
    @staticmethod
    def parse_string(pdb, str_type):
        # implement this method as per your requirement

class AbstractPdb:
    def get_type_record(self, record_number):
        # implement this method as per your requirement

# Usage example:

pdb = AbstractPdb()
reader = PdbByteReader()
str_type = "some string type"
alias_ms_type = AbstractAliasMsType(pdb, reader, str_type)
builder = StringBuilder()

try:
    alias_ms_type.emit(builder, None)  # assuming 'None' is the correct bind value
except Exception as e:
    print(f"Error: {e}")
```

Please note that Python does not have direct equivalents for Java classes like `PdbByteReader`, `RecordNumber` and `AbstractPdb`. These are placeholders in this translation. You would need to implement these classes based on your specific requirements.

Also, the usage example provided is a simple demonstration of how you might use the translated code.