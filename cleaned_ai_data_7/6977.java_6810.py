class ReturnTypeDR:
    def __init__(self, line: 'ClangLine', type: 'ClangTypeToken'):
        super().__init__(line, type)

    def accumulate_matches(self, dt: 'DataType', field_name: str, results: list) -> None:
        if field_name is not None:
            return  # Return Types do not have any field usage

        my_dt = self.get_data_type()
        if my_dt is None:
            return

        if self.is_equal(dt, my_dt):
            results.append(DataTypeReference(my_dt, None, self.get_function(), self.get_address(), self.get_context()))
