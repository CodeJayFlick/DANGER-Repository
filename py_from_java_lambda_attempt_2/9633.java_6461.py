Here's your Java code translated into Python:

```Python
import re

class ContainsTextFilter:
    def __init__(self, filter_text: str, case_sensitive: bool = True, allow_globbing: bool = False):
        self.filter_text = filter_text
        self.case_sensitive = case_sensitive
        self.allow_globbing = allow_globbing

    @property
    def pattern(self) -> re.Pattern:
        options = 0
        if not self.case_sensitive:
            options |= re.I
        return re.compile(f"{self.filter_text}", flags=options)

    def is_sub_filter_of(self, parent_filter: 'ContainsTextFilter') -> bool:
        if not isinstance(parent_filter, ContainsTextFilter):
            return False

        if (parent_filter.case_sensitive != self.case_sensitive or 
                parent_filter.allow_globbing != self.allow_globbing):
            return False

        return filter_text.lower() in parent_filter.filter_text.lower()
```

Note that Python is a dynamically-typed language and does not have direct equivalent of Java's `public`, `private` etc. access modifiers, so I've omitted them here. Also, the code assumes that you are using Python 3.x where f-strings (like `f"{self.filter_text}", flags=options`) were introduced for formatting strings.