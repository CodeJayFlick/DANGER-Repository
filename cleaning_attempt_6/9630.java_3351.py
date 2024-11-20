import re

class AbstractRegexBasedTermSplitter:
    def __init__(self, delimiter):
        self.pattern = re.compile(self.generate_pattern(delimiter))

    @staticmethod
    def generate_pattern(delim):
        return r'\s*' + re.escape(delim) + r'\s*(?=(?:[^"]*"[^"]*"*)*[^\"]*$)'

    def split(self, input_string):
        if not input_string:
            return []

        terms = self.pattern.split(input_string)
        for i in range(len(terms)):
            terms[i] = re.sub(r'"([^"]*)"|\S', r'\1', terms[i])
        return terms
