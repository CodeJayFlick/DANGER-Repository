Here is the translation of the given Java code into Python:

```Python
class DecimalSearchFormat:
    MINUS_SIGN = "-"
    BYTE = 0
    WORD = 1
    DWORD = 2
    QWORD = 3
    FLOAT = 4
    DOUBLE = 5

    def __init__(self, listener):
        self.decimal_format = self.WORD
        super().__init__("Decimal", listener)

    @property
    def tooltip(self):
        return f"Interpret values as a sequence of decimal numbers, separated by spaces"

    def set_decimal_format(self, format):
        self.decimal_format = format

    def get_options_panel(self):
        button_group = javax.swing.ButtonGroup()

        byte_button = GRadioButton("Byte", False)
        word_button = GRadioButton("Word", True)
        d_word_button = GRadioButton("DWord", False)
        q_word_button = GRadioButton("QWord", False)
        float_button = GRadioButton("Float", False)
        double_button = GRadioButton("Double", False)

        byte_button.addActionListener(lambda event: self.set_decimal_format(self.BYTE))
        word_button.addActionListener(lambda event: self.set_decimal_format(self.WORD))
        d_word_button.addActionListener(lambda event: self.set_decimal_format(self.DWORD))
        q_word_button.addActionListener(lambda event: self.set_decimal_format(self.QWORD))
        float_button.addActionListener(lambda event: self.set_decimal_format(self.FLOAT))
        double_button.addActionListener(lambda event: self.set_decimal_format(self.DOUBLE))

        button_group.add(byte_button)
        button_group.add(word_button)
        button_group.add(d_word_button)
        button_group.add(q_word_button)
        button_group.add(float_button)
        button_group.add(double_button)

        options_panel = javax.swing.JPanel()
        options_panel.setLayout(javax.swingGridLayout(3, 2))
        options_panel.add(byte_button)
        options_panel.add(word_button)
        options_panel.add(d_word_button)
        options_panel.add(q_word_button)
        options_panel.add(float_button)
        options_panel.add(double_button)

        return options_panel

    def get_search_data(self, input):
        bytes_list = []
        tokenizer = StringTokenizer(input)
        while tokenizer.hasMoreTokens():
            tok = tokenizer.nextToken()
            if tok == self.MINUS_SIGN:
                if not input.endswith(self.MINUS_SIGN):
                    return SearchData.create_invalid_input_search_data("Cannot have space after a '-'")
                return SearchData.create_incomplete_search_data("")
            try:
                bytes_list.extend([byte_value for byte_value in get_bytes(tok)])
            except (NumberFormatException, RuntimeError) as e:
                return SearchData.create_invalid_input_search_data(str(e))

        return SearchData(self.get_data_bytes(bytes_list), None)

    def get_data_bytes(self, bytes_list):
        data_bytes = [bytes_value.value for bytes_value in bytes_list]
        return bytearray(data_bytes)

    def get_bytes(self, value, n):
        bytes_list = []
        for _ in range(n):
            byte_value = int_to_byte(value)
            bytes_list.append(byte_value)
            value >>= 8
        if self.is_big_endian:
            bytes_list.reverse()
        return bytes_list

    @property
    def is_big_endian(self):
        # todo: implement this property
        pass

    def check_value(self, value, min, max):
        if not (min <= value <= max):
            raise RuntimeError(f"Number must be in the range [{min}, {max}]")

    def get_bytes(self, tok):
        switcher = {
            self.BYTE: lambda: self.get_bytes(Short.parse_short(tok), 1),
            self.WORD: lambda: self.get_bytes(Integer.parseInt(tok), 2),
            self.DWORD: lambda: self.get_bytes(Long.parseLong(tok), 4),
            self.QWORD: lambda: self.get_bytes(Long.parseLong(tok), 8),
            self.FLOAT: lambda: self.get_bytes(self.pre_process_float(tok)),
            self.DOUBLE: lambda: self.get_bytes(self.pre_process_float(tok))
        }
        return switcher[self.decimal_format]()

    def pre_process_float(self, tok):
        if 'd' in tok or 'D' in tok or 'f' in tok:
            raise NumberFormatException()
        if tok.endswith('E') or tok.endswith('e'):
            tok = tok[:-1]
        if tok.endswith('-E') or tok.endswith('-e'):
            tok = tok[:-2]

        return tok
```

Please note that this code is not a direct translation from Java to Python. It's more of an interpretation and may require some adjustments based on the specific requirements you have for your project.

Also, please be aware that the `javax.swing` package is part of the Java Standard Edition (Java SE) API, which does not exist in Python. You would need to use a GUI library like Tkinter or PyQt if you want to create graphical user interfaces with Python.