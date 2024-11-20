class MDArrayBasicType:
    ARR_NOTATION = "[]"

    def __init__(self):
        pass  # equivalent to public MDArrayBasicType( MDMang dmang )

    def parse_internal(self) -> None:
        cvMod.set_array_type()
        super().parse_internal()

    def append_array_notation(self, builder: str) -> None:
        builder += ARR_NOTATION

    def insert_cv_mod(self, builder: str) -> None:
        pass  # equivalent to do nothing.

    def insert_referred_type(self, builder: str) -> None:
        array_builder = ""
        array_builder += ARR_NOTATION
        array_builder += self.get_array_string()
        dt = self.refType

        while isinstance(dt, (MDPointerType, MDArrayReferencedType)) and not ((dt).cvMod.is_function_pointer()):
            # MDMANG SPECIALIZATION USED.
            dmang.append_array_notation(array_builder, self)
            array_builder += str(((dt)).get_array_string())
            dt = ((dt)).refType

        if isinstance(dt, MDFunctionType) and builder:
            (dt).set_from_modifier()

        dt.insert(builder)

    def insert(self, builder: str) -> None:
        # Parses, but ignores CVEIF, member and based components of all types in
        # the chain of nested types.
        array_builder = ""
        array_builder += ARR_NOTATION
        array_builder += self.get_array_string()
        dt = self.refType

        while isinstance(dt, (MDPointerType, MDArrayReferencedType)) and not ((dt).cvMod.is_function_pointer()):
            dmang.append_array_notation(array_builder, self)
            array_builder += str(((dt)).get_array_string())
            dt = ((dt)).refType

        if isinstance(dt, MDFunctionType) and builder:
            (dt).set_from_modifier()

        dt.insert(builder)

    def get_array_string(self):
        pass  # equivalent to public String getArrayString()
