import re
from typing import List

class PunctuationSeparator:
    PATTERN = re.compile(r'\s+|(?<=[\p{Punct}\p{IsPunctuation}])|(?=[\p{Punct}\p{IsPunctuation}])')

    def preprocess(self, tokens: List[str]) -> List[str]:
        return [token for token in (re.split(PATTERN.pattern(), t) for t in tokens)
                if token.strip()]
