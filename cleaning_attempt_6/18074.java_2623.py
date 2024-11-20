class BasicOperator:
    def __init__(self, token_int_type: int, series_path: str, series_value: str):
        self.series_path = series_path
        self.series_value = series_value
        self.is_leaf = True
        self.is_single = True

    @property
    def get_series_path(self) -> str:
        return self.series_path

    @property
    def get_series_value(self) -> str:
        return self.series_value

    def set_reversed_token_int_type(self):
        int_type = {1: 0, 0: 1}[self.token_int_type]
        # assuming tokenIntType is an attribute of the class
        setattr(self, 'token_int_type', int_type)

    def clone(self) -> 'BasicOperator':
        ret = BasicOperator(self.token_int_type, self.series_path, self.series_value)
        ret.token_symbol = self.token_symbol  # assuming this attribute exists
        ret.is_leaf = self.is_leaf
        ret.is_single = self.is_single
        return ret

    def __str__(self) -> str:
        return f"[{self.series_path}{self.token_symbol}{self.series_value}]"
