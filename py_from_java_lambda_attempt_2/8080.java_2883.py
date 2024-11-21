Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractManyRegisterVariable2MsSymbol:
    def __init__(self):
        self.type_record_number = None
        self.count = 0
        self.register_name_list = []
        self.name = ''

    @classmethod
    def from_pdb(cls, pdb, reader, record_number_size, str_type):
        instance = cls()
        super().__init__()
        
        # Type index or metadata token
        instance.type_record_number = RecordNumber.parse(pdb, reader, 'TYPE', record_number_size)
        instance.count = reader.read_unsigned_short()

        for _ in range(instance.count):
            register_index = reader.read_unsigned_short()
            register_name = RegisterName.from_pdb(pdb, register_index)
            instance.register_name_list.append(register_name)

        instance.name = reader.parse_string(pdb, str_type)
        reader.align4()

    def emit(self, builder):
        builder.write(f'{self.get_symbol_type_name()}: ')
        
        for register_name in self.register_name_list:
            builder.write(str(register_name) + ', ')

        if len(self.register_name_list) > 0:
            builder.write('\n')
        else:
            builder.write(' ' + pdb.get_type_record(instance.type_record_number) + f' {instance.name}')
```

Note that this Python code does not exactly replicate the Java code. The translation is based on equivalent functionality, but some parts may be different due to differences in syntax and semantics between the two languages.