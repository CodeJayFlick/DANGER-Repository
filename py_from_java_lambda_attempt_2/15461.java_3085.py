Here is the translation of the given Java code into Python:

```Python
class BertFullTokenizer:
    def __init__(self, vocabulary: dict, lower_case: bool):
        self.vocabulary = vocabulary
        self.basic_bert_preprocessors = get_preprocessors(lower_case)
        self.wordpiece_tokenizer = WordpieceTokenizer(vocabulary, '[UNK]', 200)

    @property
    def vocabulary(self) -> dict:
        return self._vocabulary

    def tokenize(self, input_text: str) -> list:
        tokens = [input_text]
        for processor in self.basic_bert_preprocessors:
            tokens = processor.process(tokens)
        return self.wordpiece_tokenizer.process(tokens)

    @property
    def wordpiece_tokenizer(self):
        return self._wordpiece_tokenizer

class WordpieceTokenizer:
    def __init__(self, vocabulary: dict, unk_token: str, max_length: int):
        self.vocabulary = vocabulary
        self.unk_token = unk_token
        self.max_length = max_length

    def process(self, tokens: list) -> list:
        # implement wordpiece tokenization logic here
        pass

class TextCleaner:
    def __init__(self, condition: callable, replacement: str):
        self.condition = condition
        self.replacement = replacement

    def process(self, tokens: list) -> list:
        return [token if not self.condition(token) else self.replacement for token in tokens]

class LambdaProcessor:
    def __init__(self, function: callable):
        self.function = function

    def process(self, tokens: list) -> list:
        return [self.function(token) for token in tokens]

def get_preprocessors(lower_case: bool) -> list:
    processors = [
        TextCleaner(lambda c: c == 0 or c == 0xfffd or NlpUtils.is_control(c), '\0'),
        TextCleaner(NlpUtils.is_whitespace, ' '),
        LambdaProcessor(str.strip),
        SimpleTokenizer(),
        LowerCaseConvertor() if lower_case else None,
        UnicodeNormalizer(1),
        TextCleaner(lambda c: Character.getType(c) == Character.NON_SPACING_MARK, '\0'),
        PunctuationSeparator(),
        LambdaProcessor(str.strip)
    ]
    return processors

class NlpUtils:
    @staticmethod
    def is_control(c):
        # implement logic here
        pass

    @staticmethod
    def is_whitespace(c):
        # implement logic here
        pass

# usage example
vocabulary = {'word1': 0, 'word2': 1}
tokenizer = BertFullTokenizer(vocabulary, lower_case=True)
tokens = tokenizer.tokenize('Hello World!')
print(tokens)