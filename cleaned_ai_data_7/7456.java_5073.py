class CFStringAnalyzer:
    NAME = "CFStrings"
    DESCRIPTION = "Parses CFString section in MachO files and inserts helpful EOL comment on all xrefs"

    CF_STRING_LABEL_PREFIX = "cf_"
    CFSTRING = "__cfstring"

    def __init__(self):
        super().__init__(self.NAME, self.DESCRIPTION, AnalyzerType.BYTE_ANALYZER)
        self.setPriority(AnalysisPriority.FORMAT_ANALYSIS.after())

    def added(self, program: Program, address_set_view: AddressSetView, task_monitor: TaskMonitor, message_log: MessageLog) -> bool:
        data_type = self.get_data_type(program)

        memory_block = program.memory().get_block(CFSTRING)
        if memory_block is None:
            return False

        current_address = memory_block.start()
        end_address = memory_block.end()

        listing = program.listing()
        listing.clear_code_units(current_address, end_address, True, task_monitor)

        while not task_monitor.is_cancelled():
            struct_end = current_address.add(data_type.length() - 1)
            if struct_end.compareTo(end_address) > 0:
                break

            try:
                data = program.listing().create_data(current_address, data_type)
                address = data.get_component(2).get_value()
                length_scalar = data.get_component(3).get_value()

                string_data = program.listing().get_data_at(address)
                if string_data is None:
                    continue

                if not isinstance(string_data.get_value(), str):
                    try:
                        listing.clear_code_units(address, address.add(length_scalar.get_value()), True)
                        string_data = listing.create_data(address, StringDataType.data_type)
                    except Exception as e:
                        message_log.append_msg("Error creating string at address " + str(address))
                else:
                    if not isinstance(string_data.get_value(), str):
                        continue

            except CodeUnitInsertionException as e:
                log.append_exception(e)
                return False
            except DataTypeConflictException as e:
                log.append_exception(e)
                return False
            except InvalidInputException as e:
                log.append_exception(e)

        return True

    def can_analyze(self, program: Program) -> bool:
        return self.is_macho_and_contains_cf_strings(program)

    def get_default_enablement(self, program: Program) -> bool:
        return self.can_analyze(program)

    def is_macho_and_contains_cf_strings(self, program: Program) -> bool:
        if program.executable_format().equals(MachoLoader.MACH_O_NAME):
            memory_blocks = program.memory().get_blocks()
            for block in memory_blocks:
                if block.name() == CFSTRING:
                    return True
        return False

    def get_data_type(self, program: Program) -> DataType:
        structure = StructureDataType("cfstringStruct", 0)
        is_64_bit = program.default_pointer_size() == 8
        if is_64_bit:
            structure.add(QWordDataType.data_type)
            structure.add(QWordDataType.data_type)
            structure.add(PointerDataType.data_type, 8)
            structure.add(LongDataType.data_type, 8)
        else:
            structure.add(DWordDataType.data_type)
            structure.add(DWordDataType.data_type)
            structure.add(PointerDataType.data_type)
            structure.add(IntegerDataType.data_type)

        return structure

    def make_comment(self, c_f_string: str) -> str:
        buf = StringBuffer()
        for i in range(len(c_f_string)):
            char = c_f_string[i]
            if char == '\t':
                buf.append("\\t")
            elif char == '\n':
                buf.append("\\n")
            elif char == '\r':
                buf.append("\\r")
            else:
                if 0x20 <= ord(char) < 0x80:
                    buf.append(char)
                else:
                    buf.append('.')

        return str(buf)

    def make_label(self, c_f_string: str) -> str:
        if len(c_f_string) == 0:
            return CF_STRING_LABEL_PREFIX + "\"\""

        buf = StringBuffer()

        for i in range(len(c_f_string)):
            char = c_f_string[i]
            if ord(char) > 0x20 and ord(char) < 0x80:
                buf.append(char)

        if len(buf) == 0:
            if self.does_string_contain_all_same_chars(c_f_string):
                switch char := c_f_string[0]:
                    case '\t':
                        return "tab(s)"
                    case '\n':
                        return "newline(s)"
                    case '\r':
                        return "creturn(s)"
                    case ' ':
                        return "space(s)"
                    default:
                        buf.append('.')
            else:
                buf.append("format(s)")

        buf.insert(0, CF_STRING_LABEL_PREFIX)

        return str(buf)

    def does_string_contain_all_same_chars(self, string: str) -> bool:
        first_char = string[0]
        for i in range(1, len(string)):
            if string[i] != first_char:
                return False

        return True
