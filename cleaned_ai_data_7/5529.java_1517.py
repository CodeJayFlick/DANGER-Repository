class VariableLocFieldFactory:
    FIELD_NAME = "Variable Location"

    def __init__(self):
        super().__init__(FIELD_NAME)

    @classmethod
    def get_storage_icon(cls, metrics, is_invalid):
        icon = EmptyIcon(18, metrics.get_height())
        if is_invalid:
            icon = MultiIcon(icon, ResourceManager.load_image("images/warning.png"))
        return icon

    def get_field(self, proxy: ProxyObj, var_width: int) -> ListingField:
        obj = proxy.get_object()
        if not self.enabled or not isinstance(obj, Variable):
            return None
        variable = Variable(obj)
        font_metrics = self.get_metrics(variable)
        has_invalid_storage = not variable.is_valid()
        loc = str(variable.get_variable_storage())
        as_ = AttributedString(self.get_storage_icon(font_metrics, has_invalid_storage), loc,
                                Color.RED if has_invalid_storage else getColor(variable),
                                font_metrics, False, None)
        field = TextFieldElement(as_, 0, 0)
        return ListingTextField.create_single_line_text_field(self, proxy, field, var_width + startX,
                                                               width, self.hl_provider)

    def get_offset_string(self, offset: int) -> str:
        off_string = f"{'-' if offset < 0 else ''}{hex(abs(offset))[2:]}"
        return off_string

    @classmethod
    def get_program_location(cls, row: int, col: int, bf: ListingField) -> ProgramLocation:
        proxy = bf.get_proxy()
        if isinstance(proxy, VariableProxy):
            variable_proxy = VariableProxy(proxy)
            sv = variable_proxy.get_object()
            return VariableLocFieldLocation(sv.get_program(), variable_proxy.get_location_address(),
                                             variable_proxy.get_object(), col)

    @classmethod
    def get_field_location(cls, bf: ListingField, index: BigInteger, field_num: int,
                           loc: ProgramLocation) -> FieldLocation:
        if not isinstance(loc, VariableLocFieldLocation):
            return None

        obj = bf.get_proxy().get_object()
        if isinstance(obj, Variable):
            sv = Variable(obj)
            var_storage_loc = VariableLocFieldLocation(loc)
            if var_storage_loc.is_location_for(sv):
                return FieldLocation(index, field_num, 0, var_storage_loc.get_char_offset())

    @classmethod
    def accepts_type(cls, category: int, proxy_object_class: Class) -> bool:
        return issubclass(proxy_object_class, Variable.__class__) and category == FieldFormatModel.FUNCTION_VARS

    @classmethod
    def new_instance(cls, format_model: FieldFormatModel, provider: HighlightProvider,
                     display_options: Options, field_options: Options) -> 'VariableLocFieldFactory':
        return cls(format_model, provider, display_options, field_options)

    @classmethod
    def get_default_color(cls):
        return OptionsGui.VARIABLE.get_default_color()
