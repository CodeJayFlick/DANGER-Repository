Here is the translation of the Java code to Python:
```
import re

class IndexUtils:
    @staticmethod
    def remove_quotation(v):
        if v.startswith("'") or v.startswith('"'):
            start = 1
        else:
            start = 0
        if v.endswith("'") or v.endswith('"'):
            end = len(v) - 1
        else:
            end = len(v)
        return v[start:end]

IndexUtils()
```
Note that I used the `re` module for regular expressions, but since we're only doing simple string manipulation, it's not actually necessary. The code is mostly equivalent to the original Java code, with some minor changes in syntax and style.

Also, note that Python doesn't have a direct equivalent of Java's `private constructor`, so I simply omitted the private constructor declaration altogether.