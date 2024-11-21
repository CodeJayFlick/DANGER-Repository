class AbstractDimensionedArrayVarBoundsUpperMsType:
    def __init__(self):
        self.rank = None
        self.type_record_number = None
        self.upper_bound = []

    @staticmethod
    def from_pdb(pdb, reader, int_size):
        instance = AbstractDimensionedArrayVarBoundsUpperMsType()
        instance.super_init(pdb, reader)
        instance.rank = reader.parse_var_sized_uint(int_size)
        instance.type_record_number = RecordNumber.from_pdb(pdb, reader, RecordCategory.TYPE, int_size)

        for i in range(instance.rank):
            upper_type_record_number = RecordNumber.from_pdb(pdb, reader, RecordCategory.TYPE, int_size)
            if not (pdb.get_type_record(upper_type_record_number) is ReferencedSymbolMsType or
                    upper_type_record_number.number == RecordNumber.T_VOID):
                raise PdbException("We are not expecting this--needs investigation")
            instance.upper_bound.append(upper_type_record_number)

    def emit(self, builder, bind):
        pdb.get_type_record(self.type_record_number).emit(builder, Bind.NONE)
        for i in range(self.rank):
            builder.append("[0:")
            builder.append(str(pdb.get_type_record(instance.upper_bound[i])))
            builder.append("]")

class PdbException(Exception):
    pass

class RecordNumber:
    @staticmethod
    def from_pdb(pdb, reader, category, int_size):
        # implementation missing here. This is a placeholder.
        return None

    def get_number(self):
        raise NotImplementedError()

class ReferencedSymbolMsType:
    pass

# usage example:

pdb = Pdb()  # implement this class
reader = Reader()
int_size = 4  # or any other size that makes sense for your use case

instance = AbstractDimensionedArrayVarBoundsUpperMsType.from_pdb(pdb, reader, int_size)
builder = StringBuilder()
bind = Bind.NONE
instance.emit(builder, bind)

print(builder.toString())
