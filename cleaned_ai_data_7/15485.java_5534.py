class SimpleTokenizer:
    def __init__(self, delimiter=" "):
        self.delimiter = delimiter

    def tokenize(self, sentence: str) -> list[str]:
        return [token for token in sentence.split() if token]

    def build_sentence(self, tokens: list[str]) -> str:
        return "".join(tokens)
