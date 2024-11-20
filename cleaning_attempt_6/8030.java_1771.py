class PdbReaderOptions:
    def __init__(self):
        self.set_defaults()

    def register_options(self, options):
        if not self.developer_mode:
            return
        help = None  # This variable seems to be unused in the original Java code.
        options.register_option("PDB One-Byte Charset Name", self.one_byte_charsetName, help,
                                 "Charset used for processing of one-byte (or multi) encoded Strings: ")
        options.register_option("PDB Wchar_t Charset Name", self.wide_char_charsetName, help,
                                 "Charset used for processing of wchar_t encoded Strings: ")

    def load_options(self, options):
        if not self.developer_mode:
            return
        self.one_byte_charsetName = options.get_string("PDB One-Byte Charset Name",
                                                         self.default_one_byte_charset_name)
        self.set_one_byte_charset_for_name(self.one_byte_charsetName)
        self.wide_char_charsetName = options.get_string("PDB Wchar_t Charset Name",
                                                        self.default_two_byte_charset_name)
        self.set_wide_char_charset_for_name(self.wide_char_charname)

    def set_defaults(self):
        self.one_byte_charsetName = "UTF-8"
        self.wide_char_charsetName = "UTF-16"

    @property
    def one_byte_charset_names(self):
        return ["utf-8", "latin1"]

    @property
    def two_byte_charset_names(self):
        return ["utf-16", "ucs2"]

    def set_one_byte_charset_for_name(self, name):
        if not self.one_byte_charset_names.__contains__(name):
            raise ValueError("Unknown OneByteCharset: {}".format(name))
        self.one_byte_charset = charset.forName(name)
        self.one_byte_charsetName = name
        return self

    def set_wide_char_charset_for_name(self, name):
        if not self.two_byte_charset_names.__contains__(name):
            raise ValueError("Unknown TwoByteCharset: {}".format(name))
        self.wide_charset = charset.forName(name)
        self.wide_char_charsetName = name
        return self

    @property
    def one_byte_charsetName(self):
        return self._one_byte_charsetName

    @one_byte_charsetName.setter
    def one_byte_charsetName(self, value):
        if not self.one_byte_charset_names.__contains__(value):
            raise ValueError("Unknown OneByteCharset: {}".format(value))
        self._one_byte_charsetName = value

    @property
    def wide_char_charname(self):
        return self._wide_char_charname

    @wide_char_charname.setter
    def wide_char_charname(self, value):
        if not self.two_byte_charset_names.__contains__(value):
            raise ValueError("Unknown TwoByteCharset: {}".format(value))
        self._wide_char_charname = value

    @property
    def one_byte_charset(self):
        return self._one_byte_charset

    @one_byte_charset.setter
    def one_byte_charset(self, value):
        self._one_byte_charset = value

    @property
    def wide_char_name(self):
        return self._wide_char_name

    @wide_char_name.setter
    def wide_char_name(self, value):
        if not self.two_byte_charset_names.__contains__(value):
            raise ValueError("Unknown TwoByteCharset: {}".format(value))
        self._wide_char_name = value

# Python does not have an exact equivalent of Java's static keyword. However,
# we can achieve the same effect by defining a class variable.
PdbReaderOptions.developer_mode = False
