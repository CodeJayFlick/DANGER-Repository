import re

class CondMatches:
    def __init__(self):
        self.strings = None
        self.regex = None
        self.partial = False

    @property
    def strings(self):
        return self._strings

    @strings.setter
    def strings(self, value):
        self._strings = value

    @property
    def regex(self):
        return self._regex

    @regex.setter
    def regex(self, value):
        self._regex = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) != 2:
            raise ValueError("Expected two expressions")
        self.strings = exprs[0]
        self.regex = exprs[1]
        self.partial = matched_pattern == 1
        return True

    def check(self, event):
        txt = [str(s) for s in self.strings.get_all(event)]
        regexes = [re.compile(r) for r in self.regex.get_all(event)]
        if len(txt) < 1 or len(regexes) < 1:
            return False
        result = True
        string_and = all(self.strings.get_and())
        regex_and = all(self.regex.get_and())
        if not string_and and regex_and:
            for t, r in zip(txt, regexes):
                if not self.matches(t, r):
                    result = False
                    break
        elif string_and and not regex_and:
            for t, r in zip(txt, regexes):
                if any(self.matches(t, rr) for rr in regexes):
                    return True
        else:
            for t, r in zip(txt, regexes):
                if self.matches(t, r):
                    result = False
                    break
        return not result

    def matches(self, str, pattern):
        return re.fullmatch(pattern.pattern(), str) if not self.partial else bool(re.search(pattern.pattern(), str))

    def __str__(self, event=None, debug=False):
        return f"{self.strings} {'' if not self.is_negated() else 'doesn\'t '} match {' '.join(self.regex)}"
