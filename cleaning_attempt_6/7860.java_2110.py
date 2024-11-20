class MDReferenceType:
    def __init__(self, dmang):
        super().__init__(dmang)
        cv_mod.set_reference_type()  # TODO: where should this go? remove constructor?

    def parse_internal(self) -> None:
        super().parse_internal()

    def parse_referenced_type(self) -> MDDataType:
        return MDDataTypeParser.parse_basic_data_type(dmang, False)

    def insert_cv_mod(self, builder: str) -> None:
        if cv_mod.is_function():
            cv_builder = StringBuilder()
            cv_mod.insert(cv_builder)
            dmang.insert_string(builder, cv_builder.toString())
        else:
            cv_mod.insert(builder)
        # Following to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
        dmang.clean_output(builder)

class MDDataTypeParser:
    @staticmethod
    def parse_basic_data_type(dmang: object, is_array: bool) -> MDDataType:
        pass

class MDMang:
    def insert_string(self, builder: str, s: str) -> None:
        pass

    def clean_output(self, builder: str) -> None:
        pass

cv_mod = ...  # TODO: initialize cv_mod
dmang = ...  # TODO: initialize dmang
