class TokenHighlights:
    def __init__(self):
        self.highlights_by_token = {}

    def copy_highlights_by_name(self):
        results = {}
        for hl in self.highlights_by_token.values():
            name = hl.get_token().get_text()
            results[name] = hl.get_color()
        return results

    @staticmethod
    def get_key(ht):
        return TokenKey(ht)

    @staticmethod
    def get_key(t):
        return TokenKey(t)

    @staticmethod
    def get_function(t):
        cfunction = t.get_clang_function()
        if cfunction is None:
            return None
        high_function = cfunction.get_high_function()
        if high_function is None:
            return None
        return high_function.get_function()

    def is_empty(self):
        return len(self.highlights_by_token) == 0

    @property
    def size(self):
        return len(self.highlights_by_token)

    def add(self, t):
        self.highlights_by_token[self.get_key(t)] = t

    def get(self, t):
        return self.highlights_by_token.get(self.get_key(t))

    def get_highlights_by_function(self, f):
        results = set()
        for key in self.get_highlight_keys(f):
            hl = self.highlights_by_token[key]
            results.add(hl)
        return results

    @staticmethod
    def get_highlight_keys(function):
        keys = set()
        entries = list(self.highlights_by_token.items())
        for entry in entries:
            highlight, token_key = entry
            if function == TokenHighlights.get_function(token_key.get_token()):
                keys.add(entry[0])
        return keys

    @staticmethod
    def contains(t):
        return self.highlights_by_token.__contains__(self.get_key(t))

    def clear(self):
        self.highlights_by_token.clear()

    def remove(self, t):
        if self.highlights_by_token.pop(self.get_key(t), None) is not None:
            return True
        else:
            return False

    @staticmethod
    def get_function(function):
        cfunction = function.get_clang_function()
        high_function = cfunction.get_high_function() if cfunction else None
        return high_function.get_function() if high_function and high_function.get_function() is not None else None


class TokenKey:
    def __init__(self, token):
        self.token = token

    @staticmethod
    def get_key(ht):
        return TokenKey(ht)

    @staticmethod
    def get_key(t):
        return TokenKey(t)

    def __hash__(self):
        if not hasattr(self, 'token'):
            raise Exception("Token is required")
        text = self.token.get_text()
        return 0 if text is None else hash(text)

    def __eq__(self, other):
        if isinstance(other, TokenKey) and self.__class__ == other.__class__':
            token1 = self.token
            token2 = other.token
            same_lines = lambda l1, l2: (l1.get_line_number() == l2.get_line_number()) if not hasattr(l1, 'get_line_number') else False

            return (
                self.token is None and other.token is None or
                self.token is None or other.token is None or
                token1.get_text() == token2.get_text() and same_lines(token1.get_line_parent(), token2.get_line_parent()) and
                token1.get_position_in_line() == token2.get_position_in_line()
            )
        return False

    def __str__(self):
        if not hasattr(self, 'token'):
            raise Exception("Token is required")
        return str(self.token)
