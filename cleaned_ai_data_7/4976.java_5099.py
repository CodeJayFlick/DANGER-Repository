class CliBlobCustomAttrib:
    def __init__(self, blob, row, metadata_stream):
        super().__init__()
        self.fixed_args = None
        self.named_args = None
        self.num_named = 0
        
        # Validate the blob prolog
        if blob.read_next_short() != 1: 
            print(f"Warning: Unexpected prolog (0x{blob.read_next_int():X})")
            return

        # Process zero to multiple FixedArgs
        params = None
        try:
            table_type = CliIndexCustomAttributeType.get_table_name(row.type_index)
            row_index = CliIndexCustomAttributeType.get_row_index(row.type_index)
            table_row = metadata_stream.get_table(table_type).get_row(row_index)

            if table_type == CliTypeTable.MemberRef:
                member_ref_sig = CliSigMethodRef(blob, table_row.signature_index)
                self.fixed_args = process_fixed_args(reader=blob.contents_reader(), params=member_ref_sig.params())
            elif table_type == CliTypeTable.MethodDef:
                method_def_sig = CliSigMethodDef(blob, table_row.sig_index)
                self.fixed_args = process_fixed_args(reader=blob.contents_reader(), params=method_def_sig.get_params())

        except InvalidInputException as e:
            print(f"Warning: Unable to process the parameters in {self.name}")

    def get_contents_data_type(self):
        struct = StructureDataType(CategoryPath(PATH), self.name, 0)
        if self.fixed_args is not None:
            for i, fixed_arg in enumerate(self.fixed_args):
                elem = fixed_arg.elem
                switch (elem):
                    case CliElementType.ELEMENT_TYPE_CHAR:
                        struct.add(WORD, f"FixedArg_{i}", "Elem ({fixed_arg.get_elem()})")
                        break

        return struct

    def get_contents_name(self):
        return "CustomAttrib"

    def get_contents_comment(self):
        return "A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute"

    # SerStrings ("serialized strings") have a length field that varies in size based on the length of the string
    # This measures and decodes the Byte, Word, or DWord length field and returns it.
    def read_ser_string_length(self):
        first_byte = self.reader.peek_next_byte()
        if (first_byte & 0x80) > 0:
            return int.from_bytes([self.reader.read_next_byte()], byteorder='big')
        else:
            return int.from_bytes([self.reader.read_next_byte(), self.reader.read_next_byte()], byteorder='big')

    def process_fixed_args(self, reader):
        fixed_args = []
        if params is None: 
            return fixed_args

        for param in params:
            elem_type_code = param.get_type().base_type_code
            switch (elem_type_code):
                case CliElementType.ELEMENT_TYPE_BOOLEAN:
                    add_fixed_arg(fixed_args, base_type_code=param.get_type(), value=self.reader.read_next_byte())
                    break

                # ... and so on for other element types ...

        return fixed_args

    def process_named_args(self):
        self.num_named = self.reader.read_next_short()

        named_args = []
        for i in range(self.num_named):
            field_or_prop = self.reader.read_next_byte()
            if (field_or_prop != CliElementType.ELEMENT_TYPE_FIELD) and (field_or_prop != CliElementType.ELEMENT_TYPE_PROPERTY):
                print(f"Warning: Invalid FieldOrProp value in NamedArg #{i+1}: 0x{int.to_bytes(field_or_prop, byteorder='big').hex()}")
                continue

            field_or_prop_type = CliElementType.from_int(self.reader.read_next_byte())

            name_len = self.read_ser_string_length()
            field_or_prop_name = self.reader.read_nextByteArray(name_len).decode('utf-8')

            named_args.append(CliNamedArg(field_or_prop, field_or_prop_type, field_or_prop_name))

        return named_args

    def add_fixed_arg(self, fixed_args, base_type_code, value):
        fixed_args.append(CliFixedArg(base_type_code, value))
