class VariableXRefFieldFactory:
    FIELD_NAME = "Variable XRef"

    def __init__(self):
        self.__init__(self.FIELD_NAME)

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.color_option_name = "XRef Color"
        self.style_option_name = "XRef Style"
        self.init_display_options()

    @staticmethod
    def get_field(proxy_obj: object, var_width: int) -> 'ListingField':
        obj = proxy_obj.get_object()
        if not VariableXRefFieldFactory.enabled or obj is None or not isinstance(obj, Variable):
            return None

        variable = Variable(obj)
        xrefs = []
        offcuts = []
        XReferenceUtils.get_variable_refs(variable, xrefs, offcuts, max_xrefs)

        if len(xrefs) + len(offcuts) == 0:
            return None

        function = variable.get_function()
        program = function.get_program()

        display_local_namespace = False
        display_block_name = False

        total_xrefs = len(xrefs) + len(offcuts)
        too_many = total_xrefs > max_x_refs

        delimiter = AttributedString("...", Color.BLACK, get_metrics())
        elements = [FieldElement() for _ in range(min(total_xrefs, max_x_refs))]

        count = 0
        for i in range(len(xrefs)):
            reference = xrefs[i]
            prefix = get_prefix(program, reference, function)
            as_string = AttributedString(str(reference.get_from_address()), Color.BLACK, get_metrics())
            if display_ref_type:
                as_string = create_ref_type_as_string(reference, as_string)

            if count < total_xrefs - 1:
                as_string = CompositeAttributedString([as_string, delimiter])
            else:
                char_spaces = [' '] * len(delimiter)
                spaces = AttributedString(''.join(char_spaces), Color.BLACK, get_metrics())
                as_string = CompositeAttributedString([as_string, spaces])

            elements[count] = TextFieldElement(as_string, count, 0)

        for i in range(len(offcuts)):
            reference = offcuts[i]
            prefix = get_prefix(program, reference, function)
            as_string = AttributedString(str(reference.get_from_address()), Color.BLACK, get_metrics())
            if display_ref_type:
                as_string = create_ref_type_as_string(reference, as_string)

            if count < total_xrefs - 1:
                as_string = CompositeAttributedString([as_string, delimiter])
            else:
                char_spaces = [' '] * len(delimiter)
                spaces = AttributedString(''.join(char_spaces), Color.BLACK, get_metrics())
                as_string = CompositeAttributedString([as_string, spaces])

            elements[count] = TextFieldElement(as_string, count, 0)

        if too_many:
            as_string = AttributedString("[more]", Color.BLACK, get_metrics())
            elements[total_xrefs - 1] = TextFieldElement(as_string, total_xrefs - 1, 0)

        return ListingTextField.create_packed_text_field(self, proxy_obj, elements, start_x + var_width,
                                                           width, max_x_refs, provider)

    @staticmethod
    def get_field_location(bf: 'ListingField', index: int, field_num: int, loc: object) -> FieldLocation:
        if not isinstance(loc, VariableXRefFieldLocation):
            return None

        obj = bf.get_proxy().get_object()
        if isinstance(obj, Variable):
            var_x_ref_loc = VariableXRefFieldLocation(loc)
            if var_x_ref_loc.is_location_for(Variable(obj)):
                return create_field_location(var_x_ref_loc.get_char_offset(), index,
                                              (ListingTextField)bf, field_num)

    @staticmethod
    def get_program_location(row: int, col: int, bf: 'ListingField') -> object:
        obj = bf.get_proxy().get_object()
        if not isinstance(obj, Variable):
            return None

        field = ListingTextField(get_field(bf.get_proxy(), 0))
        if field is not None:
            loc = field.screen_to_data_location(row, col)
            index = loc.row()

            var = Variable(obj)
            xrefs = []
            offcuts = []
            XReferenceUtils.get_variable_refs(var, xrefs, offcuts, max_x_refs)

            ref = None
            if index < len(xrefs):
                ref = xrefs[index]
            elif index < len(xrefs) + len(offcuts):
                ref = offcuts[index - len(xrefs)]

            if ref is not None:
                return VariableXRefFieldLocation(var.get_program(), var, ref.get_from_address(),
                                                  index, loc.col())

    @staticmethod
    def accepts_type(category: int, proxy_object_class: type) -> bool:
        return isinstance(proxy_object_class, Variable.__class__) and category == FieldFormatModel.FUNCTION_VARS

    @staticmethod
    def new_instance(format_model: 'FieldFormatModel', provider: object, options: object,
                     field_options: object) -> 'VariableXRefFieldFactory':
        return VariableXRefFieldFactory()
