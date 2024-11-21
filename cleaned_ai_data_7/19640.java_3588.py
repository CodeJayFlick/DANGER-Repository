class NumberOfClassCharacters:
    def __init__(self):
        self.pattern = 0

    @property
    def pattern(self):
        return self._pattern

    @pattern.setter
    def pattern(self, value):
        self._pattern = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.pattern = matched_pattern
        self.expr = exprs[0]
        return True

    def get(self, event):
        str_value = self.expr.get_single(event)
        if str_value is None:
            return None
        size = 0
        if self.pattern == 0:
            for c in str_value.encode('utf-8'):
                if c.isupper():
                    size += 1
        elif self.pattern == 1:
            for c in str_value.encode('utf-8'):
                if c.islower():
                    size += 1
        else:
            for c in str_value.encode('utf-8'):
                if c.isdigit():
                    size += 1
        return [size]

    def is_single(self):
        return True

    def get_return_type(self):
        from typing import Union
        return Union[int, None]

    def __str__(self, event=None, debug=False):
        if self.pattern == 0:
            return "number of uppercase characters"
        elif self.pattern == 1:
            return "number of lowercase characters"
        else:
            return "number of digits"

# Register the expression
def register_expression():
    from skript import Skript

    def expr_number_of_characters(exprs, matched_pattern):
        instance = NumberOfClassCharacters()
        instance.init(exprs, matched_pattern, None, None)
        return instance

    Skript.register_expression("number of upper[ ]case char(acters|s) in %string%", "number of lower[ ]case char(acters|s) in %string%", "number of digit char(acters|s) in %string%",
                               expr_number_of_characters, Long)

register_expression()
