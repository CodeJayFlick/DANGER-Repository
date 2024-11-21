Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractDerivedClassListMsType:
    def __init__(self, pdb, reader):
        self.record_numbers = []
        super().__init__(pdb, reader)

    @property
    def record_numbers(self):
        return self._record_numbers

    @record_numbers.setter
    def record_numbers(self, value):
        self._record_numbers = value

    def parse(self, int_size) -> None:
        count = self.reader.parse_var_sized_count(int_size)
        for i in range(count):
            a_record_number = RecordNumber.parse(pdb=self.pdb, reader=self.reader, category=RecordCategory.TYPE, size=int_size)
            self.record_numbers.append(a_record_number)

    def emit(self, builder: str, bind) -> None:
        ds = DelimiterState("", ", ")
        for record_number in self.record_numbers:
            type_ = self.pdb.get_type_record(record_number)
            builder += ds.out(True, str(type_))
```

Note that this Python code does not include the Java classes `AbstractPdb`, `PdbByteReader`, `RecordNumber`, and `DelimiterState` as they are specific to the Ghidra framework. You would need to implement these classes or use equivalent ones in your Python program.

Also, I've used property decorator (`@property`) to create a getter/setter for the `record_numbers`. This is not necessary if you don't plan on modifying this attribute from outside the class.