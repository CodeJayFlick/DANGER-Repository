class SleighValueConverter:
    def __init__(self):
        self.hex_value_converter = None
        self.num_value_converter = None
        self.bin_value_converter = None

    @property
    def hex_value_converter(self):
        return self._hex_value_converter

    @hex_value_converter.setter
    def hex_value_converter(self, value):
        self._hex_value_converter = value

    @property
    def num_value_converter(self):
        return self._num_value_converter

    @num_value_converter.setter
    def num_value_converter(self, value):
        self._num_value_converter = value

    @property
    def bin_value_converter(self):
        return self._bin_value_converter

    @bin_value_converter.setter
    def bin_value_converter(self, value):
        self._bin_value_converter = value

    def HEXVAL(self):
        if not hasattr(self, '_hex_value_converter'):
            raise AttributeError('HEXVAL converter is not set')
        return getattr(self, '_hex_value_converter')

    def NUMVAL(self):
        if not hasattr(self, '_num_value_converter'):
            raise AttributeError('NUMVAL converter is not set')
        return getattr(self, '_num_value_converter')

    def BINVAL(self):
        if not hasattr(self, '_bin_value_converter'):
            raise AttributeError('BINVAL converter is not set')
        return getattr(self, '_bin_value_converter')
