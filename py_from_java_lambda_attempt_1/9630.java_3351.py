Here is the translation of the given Java code into Python:

```Python
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
```

Note that Python's `re` module is used to handle regular expressions, and the `split()` method of a compiled pattern object is used instead of Java's `Pattern.split()`. The `generate_pattern()` function generates a regex pattern based on the given delimiter.