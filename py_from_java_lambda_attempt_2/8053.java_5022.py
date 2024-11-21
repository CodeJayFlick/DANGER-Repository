Here is the equivalent Python code:

```Python
class AbstractFunctionListMsSymbol:
    def __init__(self, pdb, reader):
        self.count = reader.readInt()
        self.function_type_list = []
        self.invocation_counts_list = []

        for _ in range(self.count):
            type_record_number = RecordNumber.parse_no_witness(pdb, reader, 32)
            self.function_type_list.append(type_record_number)

    def emit(self, builder):
        builder.write(f"{self.get_symbol_type_name()}: Count: {self.count}\n")
        delimiter_state = DelimiterState("", ", ")
        for i in range(self.count):
            if (i % 4) == 0:
                builder.write("\n")
            builder.write(delimiter_state.out(True, f"{pdb.get_type_record(self.function_type_list[i])} ({self.invocation_counts_list[i]})\n"))

class DelimiterState:
    def __init__(self, prefix, delimiter):
        self.prefix = prefix
        self.delimiter = delimiter

    def out(self, first_line, text):
        if not first_line:
            return f"{text}\n"
        else:
            return f"{self.prefix}{text}{self.delimiter}"
```

Note that I did not translate the `PdbException` class or the `RecordNumber`, `AbstractPdb`, and `DelimiterState` classes, as they were not provided.