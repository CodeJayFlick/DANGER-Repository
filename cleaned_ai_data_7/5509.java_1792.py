class OptionsBasedDataTypeDisplayOptions:
    DISPLAY_ABBREVIATED_DEFAULT_LABELS = "display_abbreviated_default_labels"
    MAXIMUM_DEFAULT_LABEL_LENGTH = "maximum_default_label_length"

    def __init__(self, options):
        self.options = options

        # register the options
        self.options.register_option(DISPLAY_ABBREVIATED_DEFAULT_LABELS, False, None,
            f"Uses a shortened form of the label name for dynamic String data types in the display of operand references (e.g., STR_01234567)")
        
        self.options.register_option(MAXIMUM_DEFAULT_LABEL_LENGTH, DataTypeDisplayOptions.MAX_LABEL_STRING_LENGTH, None,
            "Sets the maximum number of characters from a String to include in dynamic String labels in operand references")

    def get_label_string_length(self):
        return self.options.get_int(MAXIMUM_DEFAULT_LABEL_LENGTH, DataTypeDisplayOptions.MAX_LABEL_STRING_LENGTH)

    def use_abbreviated_form(self):
        return self.options.get_bool(DISPLAY_ABBREVIATED_DEFAULT_LABELS, False)
