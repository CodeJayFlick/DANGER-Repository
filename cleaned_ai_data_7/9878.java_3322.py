import decimal

class DecimalFormatterFactory:
    def __init__(self):
        self._decimal_format = "0.0#"
        self._number_formatter = None
        self._decimal_formatter = None

    def get_decimal_formatter(self, tf=None):
        return self._decimal_formatter

    @property
    def decimal_format(self):
        return self._decimal_format

    @decimal_format.setter
    def decimal_format(self, value):
        self._decimal_format = value
        if not self._number_formatter:
            self._number_formatter = decimal.Decimal(value)
        else:
            self._number_formatter.format = value

    def __init__(self, format_pattern="0.0#"):
        self.decimal_format = format_pattern
        self.number_formatter = None
        self.decimal_formatter = None

    @property
    def number_formatter(self):
        return self._number_formatter

    @number_formatter.setter
    def number_formatter(self, value):
        if not isinstance(value, decimal.Decimal):
            raise ValueError("Number formatter must be a Decimal object")
        self._number_formatter = value

class JFormattedTextField:
    pass  # This is just a placeholder for the Java class; you'll need to implement it in Python
