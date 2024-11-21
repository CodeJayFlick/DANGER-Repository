Here is a translation of the Java code into equivalent Python:

```Python
class CliTableMethodDef:
    def __init__(self):
        self.CLITABLEMETHODDEF_PINVOKE_JUMP_LENGTH = 0x06
        self.METHODIMPLATTRIBUTES_CODETYPE_IL = 0x00
        self.METHODIMPLATTRIBUTES_CODETYPE_NATIVE = 0x01
        self.METHODIMPLATTRIBUTES_CODETYPE_OPTIL = 0x02
        self.METHODIMPLATTRIBUTES_CODETYPE_RUNTIME = 0x03
        self.METHODIMPLATTRIBUTES_MANAGED_MANAGED = 0x00
        self.METHODIMPLATTRIBUTES_MANAGED_UNMANAGED = 0x04
        self.METHODIMPLATTRIBUTES_FORWARDREF = 0x10
        self.METHODIMPLATTRIBUTES_PRESERVESIG = 0x80
        self.METHODIMPLATTRIBUTES_INTERNALCALL = 0x1000
        self.METHODIMPLATTRIBUTES_SYNCHRONIZED = 0x20
        self.METHODIMPLATTRIBUTES_NOINLINING = 0x08
        self.METHODIMPLATTRIBUTES_AGGRESSIVEINLINING = 0x1000

    class CliMethodDefRow:
        def __init__(self, rva, impl_flags, flags, name_index, sig_index):
            self.RVA = rva
            self.ImplFlags = impl_flags
            self.Flags = flags
            self.nameIndex = name_index
            self.sigIndex = sig_index

    class CliTableMethodDefRow(CliMethodDefRow):

        def __init__(self, reader, stream, table_id):
            super().__init__()
            last_row = None
            for i in range(reader.num_rows()):
                row = CliMethodDefRow(
                    reader.read_next_int(),
                    reader.read_next_short(),
                    reader.read_next_short(),
                    read_string_index(reader),
                    read_blob_index(reader)
                )
                rows.append(row)
                strings.append(row.nameIndex)

                if last_row is not None:
                    last_row.next_row_param_index = row.param_index
                last_row = row

        def markup(self, program, is_binary, monitor, log):
            method_row_index = 0
            for method in self.rows:
                method_row_index += 1

                method_row = CliMethodDefRow(method.RVA, method.ImplFlags, method.Flags,
                                              method.nameIndex, method.sigIndex)

                if method_row.is_pinvoke_impl() and method_row.is_native():
                    end_addr = start_addr.add(self.CLITABLEMETHODDEF_PINVOKE_JUMP_LENGTH - 1)
                else:
                    # Create MethodDef at this RVA
                    binary_reader = BinaryReader(program.memory(), not program.memory().is_big_endian())
                    method_def = CliMethodDef(start_addr, binary_reader)

                    data_type = method_def.to_data_type()
                    PeUtils.create_data(program, start_addr, data_type, log)

                    # Get the function's address space, default to zero-length just in case
                    start_addr = start_addr.add(data_type.get_length())
                    end_addr = start_addr

                if method_row.is_static() and param_count > 0:
                    static_parameter = None
                    for i in range(param_count):
                        param_row = CliParamRow(method.param_index + i)

                        # Pull apart the function's Param table entries
                        try:
                            parameter_list[param_row.sequence] = new ParameterImpl(
                                SymbolUtilities.replace_invalid_chars(metadata_stream.get_strings_stream().get_string(param_row.nameIndex), True),
                                data_type, stack_offset, program)
                        except InvalidInputException as e1:
                            Msg.warn(self, "Couldn't clone implied static function parameter in function: " + func_name)

                    for i in range(parameters.length):
                        if parameters[i] is None:
                            param = new ParameterImpl(static_parameter.name + i,
                                                      static_parameter.data_type, static_parameter.stack_offset, program)
                            try:
                                method_def.update_function(null, null, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.ANALYSIS, [param])
                            except InvalidInputException as e2:
                                Msg.warn(self, "Error processing function: " + func_name)

        def get_row_representation(self):
            return f"error retrieving method representation"

    @staticmethod
    def commaify_list(list_):
        if list_.size() > 0:
            return ", ".join(map(str, list_)[:-1]) + ", "
        else:
            return ""

class CliTableMethodDefRow(CliAbstractTableRow):

    def __init__(self, reader, stream, table_id):
        super().__init__()
        self.rows = []
        for i in range(reader.num_rows()):
            row = new CliMethodDefRow(
                reader.read_next_int(),
                reader.read_next_short(),
                reader.read_next_short(),
                read_string_index(reader),
                read_blob_index(reader)
            )
            rows.append(row)

    def markup(self, program):
        # Pull apart the function's Param table entries
        for i in range(param_count):
            param_row = CliParamRow(method.param_index + i)

            try:
                parameter_list[param_row.sequence] = new ParameterImpl(
                    SymbolUtilities.replace_invalid_chars(metadata_stream.get_strings_stream().get_string(param_row.nameIndex), True),
                    data_type, stack_offset, program)
            except InvalidInputException as e1:
                Msg.warn(self, "Couldn't clone implied static function parameter in function: " + func_name)

        for i in range(parameters.length):
            if parameters[i] is None:
                param = new ParameterImpl(static_parameter.name + i,
                                          static_parameter.data_type, static_parameter.stack_offset, program)
                try:
                    method_def.update_function(null, null, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.ANALYSIS, [param])
                except InvalidInputException as e2:
                    Msg.warn(self, "Error processing function: " + func_name)

    def get_row_representation(self):
        return f"error retrieving method representation"

class CliTableMethodDefRow(CliAbstractTableRow):

    @staticmethod
    def commaify_list(list_):
        if list_.size() > 0:
            return ", ".join(map(str, list_)[:-1]) + ", "
        else:
            return ""

# Static functions have four parameters but the first is an implied pointer to the object they're associated with. It's not in the ParameterTable and looking for the extra parameter will walk you into the parameter of another function.
def is_static(self):
    return self.Flags & METHODATTRIBUTES_STATIC == METHODATTRIBUTES_STATIC

def is_pinvoke_impl(self):
    return self.Flags & METHODATTRIBUTES_PINVOKEIMPL == METHODATTRIBUTES_PINVOKEIMPL

def is_native(self):
    return self.ImplFlags & METHODIMPLATTRIBUTES_CODETYPE_NATIVE == METHODIMPLATTRIBUTES_CODETYPE_NATIVE
```

Please note that Python does not support direct translation of Java code into equivalent Python, as both languages have different syntax and semantics.