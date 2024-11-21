class ListingCodeComparisonOptions:
    OPTIONS_CATEGORY_NAME = "Listing Code Comparison"
    HELP_TOPIC = "Listing Code Comparison"

    BYTE_DIFFS_COLOR_KEY = "Byte Differences Color"
    MNEMONIC_DIFFS_COLOR_KEY = "Mnemonic Differences Color"
    OPERAND_DIFFS_COLOR_KEY = "Operand Differences Color"
    UNMATCHED_CODE_UNITS_COLOR_KEY = "Unmatched Code Units Color"
    DIFF_CODE_UNITS_COLOR_KEY = "Differing Code Units Color"

    DEFAULT_BYTE_DIFFS_BACKGROUND_COLOR_DESCRIPTION = \
        "The default background color applied to byte differences within the listing code comparison window."
    DEFAULT_MNEMONIC_DIFFS_BACKGROUND_COLOR_DESCRIPTION = \
        "The default background color applied to mnemonic differences for matched addresses within the listing code comparison window."
    DEFAULT_OPERAND_DIFFS_BACKGROUND_COLOR_DESCRIPTION = \
        "The default background color applied to operand differences within the listing code comparison window."
    DEFAULT_DIFF_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION = \
        "The default background color applied to code units with any detected differences within the listing code comparison window."
    DEFAULT_UNMATCHED_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION = \
        "The default background color applied to code units that are unmatched within the listing code comparison window by the address correlator."

    MEDIUM_SKY_BLUE_COLOR = (0x69, 0xcd, 0xe1)
    MEDIUM_GRAY_COLOR = (0xb9, 0xb9, 0xb9)
    SPRING_GREEN_COLOR = (0xaf, 0xff, 0x69)

    DEFAULT_BYTE_DIFFS_COLOR = tuple(SPRING_GREEN_COLOR) / 255.0
    DEFAULT_MNEMONIC_DIFFS_COLOR = tuple(SPRING_GREEN_COLOR) / 255.0
    DEFAULT_OPERAND_DIFFS_COLOR = tuple(SPRING_GREEN_COLOR) / 255.0
    DEFAULT_DIFF_CODE_UNITS_COLOR = tuple(MEDIUM_GRAY_COLOR) / 255.0
    DEFAULT_UNMATCHED_CODE_UNITS_COLOR = tuple(MEDIUM_SKY_BLUE_COLOR) / 255.0

    def __init__(self):
        self.byte_diffs_color = self.DEFAULT_BYTE_DIFFS_COLOR
        self.mnemonic_diffs_color = self.DEFAULT_MNEMONIC_DIFFS_COLOR
        self.operand_diffs_color = self.DEFAULT_OPERAND_DIFFS_COLOR
        self.diff_code_units_color = self.DEFAULT_DIFF_CODE_UNITS_COLOR
        self.unmatched_code_units_color = self.DEFAULT_UNMATCHED_CODE_UNITS_COLOR

    def get_default_byte_diffs_background_color(self):
        return tuple(self.DEFAULT_BYTE_DIFFS_COLOR) / 255.0

    def get_default_mnemonic_diffs_background_color(self):
        return tuple(self.DEFAULT_MNEMONIC_DIFFS_COLOR) / 255.0

    def get_default_operand_diffs_background_color(self):
        return tuple(self.DEFAULT_OPERAND_DIFFS_COLOR) / 255.0

    def get_default_diff_code_units_background_color(self):
        return tuple(self.DEFAULT_DIFF_CODE_UNITS_COLOR) / 255.0

    def get_default_unmatched_code_units_background_color(self):
        return tuple(self.DEFAULT_UNMATCHED_CODE_UNITS_COLOR) / 255.0

    def get_byte_diffs_background_color(self):
        return self.byte_diffs_color

    def get_mnemonic_diffs_background_color(self):
        return self.mnemonic_diffs_color

    def get_operand_diffs_background_color(self):
        return self.operand_diffs_color

    def get_diff_code_units_background_color(self):
        return self.diff_code_units_color

    def get_unmatched_code_units_background_color(self):
        return self.unmatched_code_units_color

    def initialize_options(self, options):
        help = {"topic": "Listing Code Comparison", "options": "Options"}
        options.set_help_location(help)

        options.register_option("Byte Differences Color", tuple(self.DEFAULT_BYTE_DIFFS_COLOR) / 255.0,
                                 help, self.DEFAULT_BYTE_DIFFS_BACKGROUND_COLOR_DESCRIPTION)
        options.register_option("Mnemonic Differences Color", tuple(self.DEFAULT_MNEMONIC_DIFFS_COLOR) / 255.0,
                                 help, self.DEFAULT_MNEMONIC_DIFFS_BACKGROUND_COLOR_DESCRIPTION)
        options.register_option("Operand Differences Color", tuple(self.DEFAULT_OPERAND_DIFFS_COLOR) / 255.0,
                                 help, self.DEFAULT_OPERAND_DIFFS_BACKGROUND_COLOR_DESCRIPTION)
        options.register_option("Differing Code Units Color", tuple(self.DEFAULT_DIFF_CODE_UNITS_COLOR) / 255.0,
                                 help, self.DEFAULT_DIFF_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION)
        options.register_option("Unmatched Code Units Color", tuple(self.DEFAULT_UNMATCHED_CODE_UNITS_COLOR) / 255.0,
                                 help, self.DEFAULT_UNMATCHED_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION)

    def load_options(self, options):
        self.byte_diffs_color = options.get_color("Byte Differences Color",
                                                  tuple(self.DEFAULT_BYTE_DIFFS_COLOR) / 255.0)
        self.mnemonic_diffs_color = options.get_color("Mnemonic Differences Color",
                                                      tuple(self.DEFAULT_MNEMONIC_DIFFS_COLOR) / 255.0)
        self.operand_diffs_color = options.get_color("Operand Differences Color",
                                                     tuple(self.DEFAULT_OPERAND_DIFFS_COLOR) / 255.0)
        self.diff_code_units_color = options.get_color("Differing Code Units Color",
                                                       tuple(self.DEFAULT_DIFF_CODE_UNITS_COLOR) / 255.0)
        self.unmatched_code_units_color = options.get_color("Unmatched Code Units Color",
                                                            tuple(self.DEFAULT_UNMATCHED_CODE_UNITS_COLOR) / 255.0)

