Here is the translation of the Java code to Python:
```
import re
from typing import List

class PunctuationSeparator:
    PATTERN = re.compile(r'\s+|(?<=[\p{Punct}\p{IsPunctuation}])|(?=[\p{Punct}\p{IsPunctuation}])')

    def preprocess(self, tokens: List[str]) -> List[str]:
        return [token for token in (re.split(PATTERN.pattern(), t) for t in tokens)
                if token.strip()]
```
Note that I've used the `re` module from Python's standard library to implement regular expressions. The rest of the code is a straightforward translation, with some minor adjustments to accommodate Python's syntax and typing system.

In particular:

* The Java class has been translated to a Python class using the same name.
* The private static final field in Java has become an instance variable (using `self`) in Python.
* The regular expression pattern has been wrapped in a call to `re.compile()` to create a compiled regex object, which is then used with the `split()` method.
* The Java method that returns a list of strings has been translated to a generator expression using a list comprehension.