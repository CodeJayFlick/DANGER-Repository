Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractDimensionedArrayVarBoundsLowerUpperMsType:
    def __init__(self):
        self.rank = None
        self.type_record_number = None
        self.lower_bound = []
        self.upper_bound = []

    @staticmethod
    def from_pdb(pdb, reader, int_size):
        instance = AbstractDimensionedArrayVarBoundsLowerUpperMsType()
        instance.rank = reader.parse_var_sized_uint(int_size)
        instance.type_record_number = RecordNumber.from_pdb(pdb, reader, RecordCategory.TYPE, int_size)
        for _ in range(instance.rank):
            lower_type_record_number = RecordNumber.from_pdb(pdb, reader, RecordCategory.TYPE, int_size)
            if not (pdb.get_type_record(lower_type_record_number) is ReferencedSymbolMsType or
                    lower_type_record_number.number == RecordNumber.T_VOID):
                raise PdbException("We are not expecting this--needs investigation")
            instance.lower_bound.append(lower_type_record_number)

            upper_type_record_number = RecordNumber.from_pdb(pdb, reader, RecordCategory.TYPE, int_size)
            if not (pdb.get_type_record(upper_type_record_number) is ReferencedSymbolMsType or
                    upper_type_record_number.number == RecordNumber.T_VOID):
                raise PdbException("We are not expecting this--needs investigation")
            instance.upper_bound.append(upper_type_record_number)

        return instance

    def emit(self, builder, bind):
        pdb.get_type_record(self.type_record_number).emit(builder, Bind.NONE)
        for i in range(self.rank):
            builder.append("[")
            builder.append(str(pdb.get_type_record(instance.lower_bound[i])))
            builder.append(":")
            builder.append(str(pdb.get_type_record(instance.upper_bound[i])))
            builder.append("]")
```

Please note that Python does not have direct equivalent of Java's `abstract` keyword. Also, the concept of a class being abstract in Java is different from its usage in C++.