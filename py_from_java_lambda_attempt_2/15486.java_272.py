Here is the equivalent Python code:

```Python
class TextCleaner:
    def __init__(self, condition, replace=None):
        self.condition = condition
        self.replace = replace if replace else None

    def clean_text(self, text: str) -> str:
        cleaned_text = ""
        for c in text:
            if self.condition(c):
                if self.replace is not None:
                    cleaned_text += self.replace
                continue
            cleaned_text += c
        return cleaned_text


def preprocess(tokens: list[str], cleaner: TextCleaner) -> list[str]:
    return [cleaner.clean_text(token) for token in tokens]
```

Note that Python does not have direct equivalents to Java's `Function` and `Collectors`, so we've implemented the equivalent logic using lambda functions and a list comprehension.