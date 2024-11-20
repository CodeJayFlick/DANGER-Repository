class DefaultValueExpression:
    def __init__(self):
        self.source = None
        self.types = []
        self.super_type = object  # default type if not specified

    @property
    def first(self):
        return None

    @first.setter
    def first(self, value):
        self._first = value

    @property
    def second(self):
        return None

    @second.setter
    def second(self, value):
        self._second = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) < 2:
            raise ValueError("Expected at least two expressions")
        self.first = exprs[0]
        self.second = exprs[1]
        return True

    def get(self, event):
        values = []
        if self.first.get(event):
            values.extend(self.first.get(event))
        else:
            values.extend(self.second.get(event) or [])
        try:
            converted_values = [self.convert_value(value) for value in values]
            return tuple(converted_values)
        except ValueError as e:
            return ()

    def convert_value(self, value):
        if not self.types:
            return value
        for type_ in self.types:
            if isinstance(value, type_):
                return value
        raise ValueError(f"Value {value} is of incorrect type")

    @property
    def source_expression(self):
        return self.source

    @source_expression.setter
    def source_expression(self, value):
        self.source = value

    def get_converted_expression(self, to_types=None):
        if not to_types:
            return self
        new_expr = DefaultValueExpression()
        new_expr.source = self
        new_expr.types = to_types
        return new_expr

    @property
    def is_single(self):
        return True  # default value for single expression

    def __str__(self, event=None, debug=False):
        if not self.first:
            first_str = "None"
        else:
            first_str = str(self.first)
        if not self.second:
            second_str = "None"
        else:
            second_str = str(self.second)
        return f"{first_str} or {second_str}"
