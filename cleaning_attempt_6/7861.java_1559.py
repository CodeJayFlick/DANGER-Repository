class MDStdNullPtrType:
    modifier_type_name = "std::nullptr_t"

    def __init__(self, dmang):
        super().__init__(dmang, 3)

    def parse_internal(self):
        cv_mod.set_other_type()

    def insert(self, builder):
        builder.length = 0
        dmang.append_string(builder, self.modifier_type_name)  # TODO: consider moving string here.
