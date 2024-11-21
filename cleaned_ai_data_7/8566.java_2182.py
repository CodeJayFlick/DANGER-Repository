class PdbPrimitiveTypeApplicator:
    def __init__(self, data_type_manager):
        self.data_type_manager = data_type_manager
        self.no_type_datatype = Undefined1DataType(data_type_manager)
        self.void_g_hidra_primitive = None
        self.char_g_hidra_primitive = None
        self.signed_char_g_hidra_primitive = None
        self_unsigned_char_g_hidra_primitive = None

        self.integral_g_hidra_primitives = {}
        self.unsigned_integral_g_hidra_primitives = {}
        self.float_g_hidra_primitives = {}
        self.complex_g_hidra_primitives = {}
        self.other_primitives = {}

    def resolve(self, data_type):
        return self.data_type_manager.resolve(data_type)

    def get_no_type(self, primitive_ms_type):
        return self.no_type_datatype

    def get_void_type(self):
        if not self.void_g_hidra_primitive:
            self.void_g_hidra_primitive = VoidDataType(self.data_type_manager)
        return self.void_g_hidra_primitive

    def get_char_type(self):
        if not self.char_g_hidra_primitive:
            self.char_g_hidra_primitive = CharDataType(self.data_type_manager)
        return self.char_g_hidra_primitive

    def get_signed_char_type(self):
        if not self.signed_char_g_hidra_primitive:
            self.signed_char_g_hidra_primitive = SignedCharDataType(self.data_type_manager)
        return self.signed_char_g_hidra_primitive

    def get_unsigned_char_type(self):
        if not self._unsigned_char_g_hidra_primitive:
            self._unsigned_char_g_hidra_primitive = UnsignedCharDataType(self.data_type_manager)
        return self._unsigned_char_g_hidra_primitive

    # ... and so on for the rest of the methods
