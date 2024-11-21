class FunctionSignatureDecompilerHover:
    NAME = "Function Signature Display"
    DESCRIPTION = "Show function signatures when hovering over a function name."
    PRIORITY = 20

    def __init__(self, tool):
        pass

    @property
    def name(self):
        return self.NAME

    @property
    def description(self):
        return self.DESCRIPTION

    @property
    def options_category(self):
        return "Decompiler Popups"

    def get_hover_component(self, program: Program, location: ProgramLocation, field_location: FieldLocation, field: Field) -> JComponent:
        if not self.enabled or not isinstance(field, ClangTextField):
            return None

        token = (field).get_token(field_location)
        if isinstance(token, ClangFuncNameToken):
            function = DecompilerUtils.get_function(program, token)
            if function is None:
                return None
            content = ToolTipUtils.get_tooltip_text(function, False)
            return self.create_tooltip_component(content)

        elif isinstance(token, ClangVariableToken):
            vn = (token).get_varnode()
            scalar = self.get_scalar(vn)
            function = self.get_function_at_address(program, scalar)
            if function is not None:
                content = ToolTipUtils.get_tooltip_text(function, False)
                content = f"{content}<br/><br/>{self.create_tooltip_component(f"Reference to Function")}"
                return self.create_tooltip_component(content)

        return None

    def get_scalar(self, vn: Varnode) -> Scalar:
        if vn is None or not isinstance(vn.get_high(), HighConstant):
            return None
        hv = (vn).get_high()
        offset = vn.get_offset()
        sz = vn.get_size()
        is_signed = True
        if isinstance(hv.get_data_type(), AbstractIntegerDataType):
            is_signed = ((AbstractIntegerDataType) hv.get_data_type()).is_signed()

        if sz > 8:
            return None

        return Scalar(sz * 8, offset, is_signed)

    def get_function_at_address(self, program: Program, scalar: Scalar) -> Function:
        if scalar is None or not isinstance(scalar, (int)):
            return None
        factory = program.get_address_factory()
        space = factory.get_default_address_space()

        try:
            as_address = factory.get_address(space.get_space_id(), scalar)
            return program.get_listing().get_function_at(as_address)

        except AddressOutOfBoundsException:
            return None

    def create_tooltip_component(self, content: str) -> JComponent:
        pass
