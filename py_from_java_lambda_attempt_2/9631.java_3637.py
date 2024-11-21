Here is the translation of the given Java code into Python:

```Python
import re

class CharacterTermSplitter:
    def __init__(self, delimiter):
        self.delimiter = str(delimiter)

    def split(self, string):
        return re.split(str(self.delimiter), string)
```

In this Python version, we have a class `CharacterTermSplitter` with an initializer method (`__init__`) that takes in the character to be used as the delimiter. The `split` method uses the `re.split` function from the built-in `re` module (which is for regular expressions) to split the input string into substrings using the given delimiter.