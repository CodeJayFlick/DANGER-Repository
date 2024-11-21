class XRefHeaderFieldFactory:
    XREF_FIELD_NAME = "XRef Header"

    def __init__(self):
        super().__init__(XREF_FIELD_NAME)

    def __init__(self, model: 'FieldFormatModel', hl_provider: 'HighlightProvider',
                 display_options: 'Options', field_options: 'ToolOptions'):
        super().__init__(model, hl_provider, display_options, field_options)
        self.color_option_name = "XRef Color"
        self.style_option_name = "XRef Style"
        self.init_display_options()

    def get_field(self, proxy_obj: object, var_width: int) -> 'ListingField':
        obj = proxy_obj.get_object()
        if not self.enabled or not isinstance(obj, CodeUnit):
            return None
        cu = CodeUnit(obj)
        head_string = self._get_xref_header_string(cu)
        if head_string is None or len(head_string) == 0:
            return None
        as_ = AttributedString(head_string, color=self.color, get_metrics())
        field = TextFieldElement(as_, 0, 0)
        return ListingTextField.create_single_line_text_field(self, proxy_obj, field,
                                                               self.start_x + var_width, width,
                                                               hl_provider)

    def _get_xref_header_string(self, cu: 'CodeUnit') -> str:
        if cu is None:
            return None
        prog = cu.get_program()
        xref_count = prog.reference_manager().reference_count_to(cu.min_address())
        offcuts = XReferenceUtils.get_offcut_references(cu, self.max_xrefs)
        offcut_count = len(offcuts)

        if offcut_count > 0:
            modifier = ""
            if offcut_count == self.max_xrefs:
                modifier = "+"
            return f"XREF[{xref_count},{offcut_count}{modifier}]: "
        elif xref_count > 0:
            return f"XREF[{xref_count}]: "

        return None

    def get_program_location(self, row: int, col: int, bf: 'ListingField') -> 'ProgramLocation':
        obj = bf.get_proxy().get_object()
        if not isinstance(obj, CodeUnit):
            return None
        cu = CodeUnit(obj)
        cpath = None
        if isinstance(cu, Data):
            cpath = cu.component_path()

        addr = cu.min_address()
        return XRefHeaderFieldLocation(cu.program(), addr, cpath, col)

    def get_field_location(self, bf: 'ListingField', index: int, field_num: int,
                            loc: 'ProgramLocation') -> 'FieldLocation':
        if not isinstance(loc, XRefHeaderFieldLocation):
            return None
        xref_loc = XRefHeaderFieldLocation(loc)
        if xref_loc.ref_address() is not None:
            return None

        if not self.has_same_path(bf, loc):
            return None

        return FieldLocation(index, field_num, xref_loc.row(), xref_loc.char_offset())

    def new_instance(self) -> 'XRefHeaderFieldFactory':
        return XRefHeaderFieldFactory()
