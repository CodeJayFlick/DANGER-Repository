class LongLongDataType:
    serialVersionUID = 1

    dataType = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__("longlong", True, dtm)

    @property
    def length(self):
        return self.data_organization.long_long_size

    @property
    def has_language_dependent_length(self):
        return True

    @property
    def description(self):
        return "Signed Long Long Integer (compiler-specific size)"

    @property
    def c_declaration(self):
        return C_SIGNED_LONGLONG

    @property
    def opposite_signedness_data_type(self):
        if not hasattr(self, '_opposite_signedness_data_type'):
            self._opposite_signedness_data_type = UnsignedLongLongDataType().clone(self.data_type_manager)
        return self._opposite_signedness_data_type

    def clone(self, dtm=None):
        if dtm == self.data_type_manager:
            return self
        else:
            return LongLongDataType(dtm)

    @property
    def c_type_declaration(self, data_organization):
        return f"{self.name} long long {False}"
