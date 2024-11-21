class FieldNameFieldFactory:
    FIELD_NAME = "Field Name"
    ARRAY_INDEX_FORMAT_NAME = f"{FormatManager.ARRAY_OPTIONS_GROUP}{Options.DELIMITER}Array Index Format"

    class IndexFormat(enum.Enum):
        decimal = (10, "", "")
        hex = (16, "0x", "")
        octal = (8, "0", "")
        binary = (2, "", "b")

    def __init__(self):
        super().__init__(FieldNameFieldFactory.FIELD_NAME)

    @classmethod
    def create(cls, model: FieldFormatModel, hl_provider: HighlightProvider,
               display_options: Options, field_options: ToolOptions) -> 'FieldNameFieldFactory':
        instance = cls()
        instance.model = model
        instance.hl_provider = hl_provider
        instance.display_options = display_options
        instance.field_options = field_options

    def get_field_name(self, data):
        parent = data.get_parent()
        if parent and isinstance(parent.get_data_type(), Array):
            index_str = f"{self.format.prefix}{data.get_component_index():d}{self.format.postfix}"
            return f"[{index_str}]"
        return data.get_field_name()

    def field_options_changed(self, options: Options, option_name: str, old_value: object,
                               new_value: object):
        super().field_options_changed(options, option_name, old_value, new_value)
        if options.name == GhidraOptions.CATEGORY_BROWSER_FIELDS:
            if option_name == FieldNameFieldFactory.ARRAY_INDEX_FORMAT_NAME:
                self.format = IndexFormat(new_value)
                self.model.update()

    def get_field(self, proxy: ProxyObj, var_width: int):
        obj = proxy.get_object()
        if not self.enabled or not isinstance(obj, Data):
            return None
        data = Data(obj)

        field_name = self.get_field_name(data)
        if not field_name:
            return None

        attributed_string = AttributedString(field_name, color=self.color, metrics=self.metrics)
        text = TextFieldElement(attributed_string, 0, 0)

        return ListingTextField.create_single_line_text_field(self, proxy, text,
                                                               self.start_x + var_width, width,
                                                               hl_provider)

    def get_program_location(self, row: int, col: int, bf: ListingField):
        obj = bf.get_proxy().get_object()
        if not isinstance(obj, Data):
            return None
        data = Data(obj)
        return FieldNameFieldLocation(data.get_program(), data.get_min_address(),
                                       data.get_component_path(), self.get_field_name(data), col)

    def get_field_location(self, bf: ListingField, index: int, field_num: int,
                            program_loc: ProgramLocation):
        if not isinstance(program_loc, FieldNameFieldLocation):
            return None
        loc = FieldNameFieldLocation(program_loc)
        if not self.has_same_path(bf, loc):
            return None

        return FieldLocation(index, field_num, 0, loc.get_char_offset())

    def accepts_type(self, category: int, proxy_object_class: Class) -> bool:
        if not CodeUnit.class.is_assignable_from(proxy_object_class):
            return False
        return (category == FieldFormatModel.OPEN_DATA or category == FieldFormatModel.ARRAY)

    @classmethod
    def new_instance(cls, format_model: FieldFormatModel,
                     provider: HighlightProvider, tool_options: ToolOptions,
                     field_options: ToolOptions) -> 'FieldNameFieldFactory':
        return cls().create(format_model, provider, tool_options, field_options)

    def get_default_color(self):
        return OptionsGui.FIELD_NAME.get_default_color()
