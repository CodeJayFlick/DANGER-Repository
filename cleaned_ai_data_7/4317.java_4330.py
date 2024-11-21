class MakeStringsTask:
    LOCALIZATION_SEPARATOR = "@"
    MAX_LABEL_LENGTH = 60

    def __init__(self, program, found_strings=None, offset=0, alignment=1,
                 auto_label=False, add_alignment_bytes=True, allow_truncate=False,
                 make_array=False):
        self.program = program
        if found_strings is None:
            self.found_strings = []
        else:
            self.found_strings = found_strings
        self.offset = offset
        self.alignment = alignment
        self.auto_label = auto_label
        self.add_alignment_bytes = add_alignment_bytes
        self.allow_truncate = allow_truncate
        self.make_array = make_array

    def do_run(self, monitor):
        for found_string in self.found_strings:
            if monitor.is_cancelled():
                break
            self.make_string(found_string)
            monitor.increment_progress(1)

    def make_string(self, found_string):
        string_instance = found_string.get_data_instance()
        if self.offset != 0:
            string_instance = string_instance.get_char_offcut(self.offset)
        if not string_instance.get_string_length():
            return
        address = string_instance.get_address()
        length = string_instance.get_data_length()
        padding_length = self.get_padding_length(address, length)

        conflicting_address = DataUtilities.find_first_conflicting_address(
            self.program, address, length, True)
        if conflicting_address is not None:
            if not self.allow_truncate:
                self.has_errors = True
                return
            length = int(conflicting_address.subtract(address))
            padding_length = 0

        if padding_length > 0:
            conflicting_address = DataUtilities.find_first_conflicting_address(
                self.program, address.add(length), padding_length, True)
            if conflicting_address is not None:
                padding_length = 0
        else:
            data_type_to_create = string_instance.get_string_data_type_guess()
            if not self.is_pascal(data_type_to_create):
                length += padding_length
                padding_length = 0

        try:
            data = DataUtilities.create_data(
                self.program, address, data_type_to_create, length, False,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
            events.append(StringAddedEvent(data_type_to_create, address, len(data)))
        except Exception as e:
            self.has_errors = True

        if padding_length > 0:
            try:
                self.program.get_listing().create_data(
                    address.add(length), AlignmentDataType(), padding_length)
            except Exception as e:
                pass
        else:
            data_type_to_create = string_instance.get_string_data_type_guess()
            if not self.is_pascal(data_type_to_create):
                length += padding_length
                padding_length = 0

    def is_pascal(self, data_type):
        return (isinstance(data_type, PascalString255DataType) or
               isinstance(data_type, PascalStringDataType) or
               isinstance(data_type, PascalUnicodeDataType))

    def create_label(self, address, label):
        if len(label) > self.MAX_LABEL_LENGTH:
            label = label[:self.MAX_LABEL_LENGTH] + self.LOCALIZATION_SEPARATOR + str(address)
        try:
            do_create_label(address, label)
        except DuplicateNameException as e1:
            pass
        except InvalidInputException as e2:
            Msg.debug(self, "Unexpected exception creating symbol", e2)

    def create_localized_label(self, address, label):
        valid_label = SymbolUtilities.replace_invalid_chars(label, False)
        localized_label = valid_label + self.LOCALIZATION_SEPARATOR + str(address)
        try:
            do_create_label(address, localized_label)
        except DuplicateNameException as e1:
            pass
        except InvalidInputException as e2:
            Msg.debug(self, "Unexpected exception creating symbol", e2)

    def do_create_label(self, address, label):
        if self.program.get_symbol_table().get_primary_symbol(address) is None:
            self.program.get_symbol_table().create_label(address, label, SourceType.ANALYSIS)
        else:
            sym = self.program.get_symbol_table().get_primary_symbol(address)
            if not sym.name.equals(label):
                new_sym = self.program.get_symbol_table().create_label(
                    address, label, SourceType.ANALYSIS
                )
                new_sym.set_primary()

    def label_already_exists(self, address, name):
        symbol_table = self.program.get_symbol_table()
        symbols = symbol_table.get_symbols_as_iterator(address)
        for symbol in symbols:
            if symbol.name.equals(name):
                return True
        return False

    def get_padding_length(self, address, length):
        if not self.add_alignment_bytes or length % self.alignment == 0:
            return 0
        pad_length = self.alignment - (length % self.alignment)
        try:
            bytes = bytearray(pad_length)
            num = self.program.get_memory().get_bytes(address.add(length), bytes, 0, pad_length)
            if num != pad_length:
                return 0
            for i in range(len(bytes)):
                if bytes[i] != 0:
                    return 0
        except MemoryAccessException as e1:
            return 0
        return pad_length

    def has_errors(self):
        return self.has_errors

    def get_string_events(self):
        return self.events


class StringEvent:
    pass


class PascalString255DataType:
    pass


class PascalStringDataType:
    pass


class PascalUnicodeDataType:
    pass


class AlignmentDataType:
    pass
