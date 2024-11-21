class DemangledString:
    def __init__(self, mangled, original_demangled, name, string, length, unicode):
        self.string = string
        self.length = length
        self.unicode = unicode
        super().__init__(mangled, original_demangled)
        self.name = name

    def get_signature(self, format=False):
        buffer = StringBuilder()
        if hasattr(self, 'special_prefix'):
            buffer.append(self.special_prefix)
        buffer.append(self.string)
        return str(buffer)

    @staticmethod
    def has_label(program, address, label):
        symbol_table = program.get_symbol_table()
        for s in symbol_table.get_symbols(address):
            if label == s.name:
                return True
        return False

    def apply_to(self, program, address, options, monitor):
        label = self.build_string_label()
        if DemangledString.has_label(program, address, label):
            return True  # This string has already been applied

        if not super().apply_to(program, address, options, monitor):
            return False

        s = program.get_symbol_table().get_primary_symbol(address)
        if s and s.symbol_type == 'FUNCTION':
            Msg.error(self, f"Failed to demangled string at {address} due to existing function")
            return False

        cmd = CreateStringCmd(address, -1, self.is_unicode())
        cmd.apply_to(program)

        symbol = apply_demangled_name(label, address, True, False, program)
        return symbol is not None

    def build_string_label(self):
        if hasattr(self, 'special_prefix'):
            # a special prefix implies that the author wishes to apply the string exactly as-is
            return self.name

        len_ = len(self.string)
        buf = StringBuilder(len_)
        for i in range(len_):
            c = self.string[i]
            if StringUtilities.is_displayable(c) and (c != ' '):
                buf.append(c)
            else:
                buf.append('_')
        prefix = f"u_" if self.unicode else "s_"
        return f"{prefix}{buf}"

    def get_string(self):
        return self.string

    def get_length(self):
        return self.length

    def is_unicode(self):
        return self.unicode
