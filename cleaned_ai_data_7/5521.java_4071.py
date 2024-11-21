class SpacerFieldFactory:
    FIELD_NAME = "Spacer"

    def __init__(self):
        super().__init__(FIELD_NAME)

    def __init__(self, model: 'FieldFormatModel', hs_provider: 'HighlightProvider',
                 display_options: dict, field_options: dict):
        super().__init__(model, hs_provider, display_options, field_options)

    def __init__(self, text: str, model: 'FieldFormatModel', hs_provider: 'HighlightProvider',
                 display_options: dict, field_options: dict):
        super().__init__(text, model, hs_provider, display_options, field_options)
        self.text = text

    def set_text(self, text: str) -> None:
        if text and not text.strip():
            text = None
        self.text = text

    def set_text(self) -> None:
        new_text = OptionDialog.show_input_single_line_dialog(None, "Input Spacer Text", "Text", self.text)
        if new_text:
            new_text = new_text.strip()
            if not new_text:
                self.text = None
            else:
                self.text = new_text
        model.update()

    def get_text(self) -> str:
        return self.text

    def get_field(self, proxy: 'ProxyObj', var_width: int) -> dict:
        if enabled and text:
            as_ = AttributedString(text, color, get_metrics())
            field = TextFieldElement(as_, 0, 0)
            return ListingTextField.create_single_line_text_field(self, proxy, field, start_x + var_width,
                                                                    width, hl_provider)

    def get_field_text(self) -> str:
        if not self.text:
            return ""
        return self.text

    def get_field_location(self, bf: 'ListingField', index: int, field_num: int,
                            program_loc: 'ProgramLocation') -> dict or None:
        if not isinstance(program_loc, SpacerFieldLocation):
            return None
        loc = SpacerFieldLocation(program_loc)
        if loc.get_text() == self.text:
            return FieldLocation(index, field_num, 0, loc.get_char_offset())
        return None

    def get_program_location(self, row: int, col: int, bf: 'ListingField') -> dict or None:
        obj = bf.get_proxy().get_object()
        if not isinstance(obj, CodeUnit):
            return None
        cu = CodeUnit(obj)
        cpath = None
        if isinstance(obj, Data):
            cpath = ((Data) obj).get_component_path()

        return SpacerFieldLocation(cu.get_program(), cu.get_min_address(), cpath, col, self.text)

    def get_string_to_highlight(self, bf: 'ListingTextField', row: int, col: int,
                                 loc: 'ProgramLocation') -> str or None:
        if not loc:
            return None
        s = (SpacerFieldLocation(loc)).get_text()
        return StringUtilities.find_word(s, col)

    def accepts_type(self, category: int, proxy_object_class: type) -> bool:
        return True

    def new_instance(self, format_model: 'FieldFormatModel', provider: 'HighlightProvider',
                     options: dict, field_options: dict):
        return SpacerFieldFactory(format_model, provider, options, field_options)
