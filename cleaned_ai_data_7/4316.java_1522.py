class FoundStringWithWordStatus:
    def __init__(self, source=None):
        if source is not None:
            self.address = source.get_address()
            self.length = source.get_length()
            self.string_data_type = source.get_data_type()
            self.defined_state = source.get_defined_state()
            self.is_high_confidence_word = False
        else:
            self.address = None
            self.length = 0
            self.string_data_type = None
            self.defined_state = None
            self.is_high_confidence_word = False

    def __str__(self):
        return f"{super().__str__()}, high confidence={self.is_high_confidence_word}"
