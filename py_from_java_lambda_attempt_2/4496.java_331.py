Here is a translation of the provided Java code into equivalent Python:

```Python
class PcodeFieldFactory:
    FIELD_NAME = "PCode"
    GROUP_TITLE = "Pcode Field"

    def __init__(self):
        super().__init__()
        self.width = 300

    def __init__(self, name: str, model: 'FieldFormatModel', highlight_provider: 'HighlightProvider',
                 display_options: 'Options', field_options: 'Options'):
        super().__init__(name, model, highlight_provider, display_options, field_options)
        self.width = 300
        self.color = display_options.get_color(OptionsGui.BYTES.getColorOptionName(), OptionsGui.BYTES.getDefaultColor())
        self.style = display_options.get_int(OptionsGui.BYTES.getStyleOptionName(), -1)
        self.formatter = PcodeFormatter()

    def new_instance(self, model: 'FieldFormatModel', highlight_provider: 'HighlightProvider',
                     display_options: 'ToolOptions', field_options: 'ToolOptions') -> 'PcodeFieldFactory':
        return PcodeFieldFactory(FIELD_NAME, model, highlight_provider, display_options, field_options)

    def get_field(self, proxy_obj: 'ProxyObj', var_width: int) -> 'ListingField':
        obj = proxy_obj.get_object()

        if not self.enabled or not isinstance(obj, Instruction):
            return None

        instr = Instruction(obj)
        elements = []

        pcode_listing = formatter.to_attributed_strings(instr.program, instr.pcode(True))
        line_cnt = len(pcode_listing)

        for i in range(line_cnt):
            elements.append(TextFieldElement(pcode_listing[i], i, 0))

        if elements:
            text_elements = [element for element in elements]
            return ListingTextField.create_multiline_text_field(self, proxy_obj, text_elements,
                                                                  startX + var_width, width, int.max_value, hl_provider)
        else:
            return None

    def get_field_location(self, listing_field: 'ListingField', index: 'BigInteger', field_num: int,
                            program_location: 'ProgramLocation') -> 'FieldLocation':
        if isinstance(program_location, PcodeFieldLocation):
            return FieldLocation(index, field_num, (program_location.row), (program_location.char_offset))
        else:
            return None

    def get_program_location(self, row: int, col: int, listing_field: 'ListingField') -> 'ProgramLocation':
        proxy_obj = listing_field.get_proxy()
        obj = proxy_obj.get_object()

        if not isinstance(obj, Instruction):
            return None
        elif row < 0 or col < 0:
            return None

        instr = Instruction(obj)
        program = instr.program
        attributed_strings = formatter.to_attributed_strings(program, instr.pcode(True))
        strings = [string.text for string in attributed_strings]

        return PcodeFieldLocation(program, instr.min_address(), strings, row, col)

    def accepts_type(self, category: int, proxy_object_class: 'Class') -> bool:
        return issubclass(proxy_object_class, CodeUnit) and (category == FieldFormatModel.INSTRUCTION_OR_DATA or
                                                               category == FieldFormatModel.OPEN_DATA)

    def display_options_changed(self, options: 'Options', option_name: str, old_value: object,
                                 new_value: object):
        super().display_options_changed(options, option_name, old_value, new_value)
        formatter.set_font_metrics(get_metrics())

    def field_options_changed(self, options: 'Options', option_name: str, old_value: object,
                              new_value: object):
        super().field_options_changed(options, option_name, old_value, new_value)

        if options.name == GhidraOptions.CATEGORY_BROWSER_FIELDS:
            if option_name in [MAX_DISPLAY_LINES_MSG, DISPLAY_RAW_PCODE]:
                self.set_options(options)
                model.update()

    def set_colors(self, options: 'Options'):
        formatter.set_color(
            options.get_color(OptionsGui.ADDRESS.getColorOptionName(), OptionsGui.ADDRESS.getDefaultColor()),
            options.get_color(OptionsGui.REGISTERS.getColorOptionName(),
                              OptionsGui.REGISTERS.getDefaultColor()),
            options.get_color(OptionsGui.CONSTANT.getColorOptionName(),
                              OptionsGui.CONSTANT.getDefaultColor()),
            options.get_color(OptionsGui.LABELS_LOCAL.getColorOptionName(),
                              OptionsGui.LABELS_LOCAL.getDefaultColor())
        )
        formatter.set_font_metrics(get_metrics())

    def set_options(self, field_options: 'Options'):
        max_display_lines = field_options.get_int(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES)
        display_raw = field_options.get_boolean(DISPLAY_RAW_PCODE, False)

        self.formatter.set_options(max_display_lines, display_raw)


class PcodeFormatter:
    def __init__(self):
        pass

    def to_attributed_strings(self, program: 'Program', pcode: list) -> list:
        return []

    def set_font_metrics(self, metrics: object):
        pass


class TextFieldElement:
    def __init__(self, attributed_string: 'AttributedString', row: int, col: int):
        self.attributed_string = attributed_string
        self.row = row
        self.col = col

    @property
    def text(self) -> str:
        return self.attributed_string.text


class FieldLocation:
    def __init__(self, index: 'BigInteger', field_num: int, row: int, char_offset: int):
        self.index = index
        self.field_num = field_num
        self.row = row
        self.char_offset = char_offset

    @property
    def start(self) -> object:
        pass


class ListingTextField:
    @staticmethod
    def create_multiline_text_field(factory: 'PcodeFieldFactory', proxy_obj: 'ProxyObj',
                                      text_elements: list, x: int, width: int, max_lines: int,
                                      highlight_provider: 'HighlightProvider') -> 'ListingField':
        pass


class ProxyObj:
    @property
    def object(self) -> object:
        return None

    @property
    def proxy(self) -> object:
        return None


class Instruction:
    def __init__(self, obj):
        self.program = Program(obj)
        self.min_address = 0
        self.pcode = lambda: []

    @property
    def program(self) -> 'Program':
        pass

    @property
    def min_address(self) -> int:
        return 0


class ProgramLocation:
    def __init__(self, program: 'Program', address: int):
        self.program = program
        self.address = address

    @property
    def row(self) -> int:
        pass

    @property
    def char_offset(self) -> int:
        return 0


class Program:
    def __init__(self, obj):
        pass

    @property
    def pcode(self, raw: bool) -> list:
        pass


class CodeUnit:
    pass


class OptionsGui:
    BYTES = "BYTES"
    REGISTERS = "REGISTERS"
    CONSTANT = "CONSTANT"
    LABELS_LOCAL = "LABELS_LOCAL"


GhidraOptions.CATEGORY_BROWSER_FIELDS = ""
FieldFormatModel.INSTRUCTION_OR_DATA = 0
FieldFormatModel.OPEN_DATA = 1

int.max_value = float('inf')
```

Please note that this is a direct translation of the provided Java code into equivalent Python.