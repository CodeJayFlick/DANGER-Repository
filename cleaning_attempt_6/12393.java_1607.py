class StringRenderBuilder:
    DOUBLE_QUOTE = '"'
    SINGLE_QUOTE = "'"
    MAX_ASCII = 0x80

    def __init__(self, char_size):
        self.char_size = char_size
        self.quote_char = self.DOUBLE_QUOTE
        self.sb = StringBuilder()

    def starts_with_quoted_text(self):
        return len(self.sb) > 0 and self.sb[0] == self.quote_char

    def add_string(self, str):
        if not self.byte_mode:
            self.ensure_text_mode()
        else:
            self.ensure_byte_mode()
        self.sb.append(str)

    def add_escaped_char(self, ch):
        if not self.byte_mode:
            self.ensure_text_mode()
        else:
            self.ensure_byte_mode()
        self.sb.append('\\')
        self.sb.append(ch)

    def add_code_point_char(self, codepoint):
        if not self.byte_mode:
            self.ensure_text_mode()
        else:
            self.ensure_byte_mode()
        if codepoint == self.quote_char:
            self.sb.append('\\')
        self.sb.appendCodePoint(codepoint)

    def add_code_point_value(self, codepoint):
        if self.byte_mode:
            self.ensure_byte_mode()
        val_str = hex(codepoint).upper().zfill(2 * (self.char_size + 1))
        self.sb.append(val_str)

    def add_byte_seq(self, bytes):
        if not self.byte_mode and len(bytes) > 0:
            self.ensure_text_mode()
        for i in range(len(bytes)):
            val_str = hex(int.from_bytes([bytes[i]], 'big')).upper().zfill(2)
            self.sb.append(val_str + 'h')
        if not self.byte_mode:
            self.ensure_byte_mode()

    def add_escapes_code_point(self, codepoint):
        escape_char = 'x' if codepoint < self.MAX_ASCII else ('u' if 0 <= codepoint < 65536 else 'U')
        cp_digits = len(hex(codepoint).upper().replace(' ', '')) - 1
        s = hex(codepoint).upper()
        self.sb.append('\\')
        self.sb.append(escape_char)
        self.sb.append(StringUtilities.pad(s, '0', cp_digits))

    def to_string(self):
        str = self.sb.toString()
        if not self.byte_mode:
            # close the quoted text mode in the local string
            str += self.quote_char
        return str

    def ensure_text_mode(self):
        if len(self.sb) == 0:
            self.sb.append(self.quote_char)
        elif self.byte_mode:
            self.sb.append(',')
            self.sb.append(self.quote_char)
        self.byte_mode = False

    def ensure_byte_mode(self):
        if not self.byte_mode:
            self.sb.append(self.quote_char)
        if len(self.sb) > 0:
            self.sb.append(',')
        self.byte_mode = True
