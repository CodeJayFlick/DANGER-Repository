class ExprIndexOf:
    def __init__(self):
        self.first = None
        self.haystack = None
        self.needle = None

    @property
    def first(self):
        return self._first

    @first.setter
    def first(self, value):
        self._first = value

    @property
    def haystack(self):
        return self._haystack

    @haystack.setter
    def haystack(self, value):
        self._haystack = value

    @property
    def needle(self):
        return self._needle

    @needle.setter
    def needle(self, value):
        self._needle = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if isinstance(exprs[0], str) and isinstance(exprs[1], str):
            self.first = (parse_result.mark == 0)
            self.needle = exprs[0]
            self.haystack = exprs[1]
            return True
        else:
            return False

    def get(self, e):
        if not hasattr(self, 'haystack') or not hasattr(self, 'needle'):
            return []
        h = self.haystack.get_single(e)
        n = self.needle.get_single(e)
        if h is None or n is None:
            return [None]
        i = 1 + (0 if self.first else len(h) - 1) if h.find(n) == -1 else h.index(n)
        return [(i,)]

    def is_single(self):
        return True

    def get_return_type(self):
        from typing import Union
        return Union[int]

    def __str__(self, e=None, debug=False):
        return f"the {('first' if self.first else 'last')} index of {self.needle} in {self.haystack}"
