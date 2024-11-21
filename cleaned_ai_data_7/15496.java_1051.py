class QATranslator:
    def __init__(self):
        pass

    @property
    def batchifier(self):
        return self._batchifier

    @batchifier.setter
    def batchifier(self, value):
        self._batchifier = value

    @property
    def tokenizer_name(self):
        return self._tokenizer_name

    @tokenizer_name.setter
    def tokenizer_name(self, value):
        self._tokenizer_name = value

    @property
    def vocab(self):
        return self._vocab

    @vocab.setter
    def vocab(self, value):
        self._vocab = value

    @property
    def locale(self):
        return self._locale

    @locale.setter
    def locale(self, value):
        self._locale = value

    @property
    def to_lower_case(self):
        return self._to_lower_case

    @to_lower_case.setter
    def to_lower_case(self, value):
        self._to_lower_case = value

    @property
    def include_token_types(self):
        return self._include_token_types

    @include_token_types.setter
    def include_token_types(self, value):
        self._include_token_types = value

    @property
    def padding(self):
        return self._padding

    @padding.setter
    def padding(self, value):
        self._padding = value

    @property
    def truncation(self):
        return self._truncation

    @truncation.setter
    def truncation(self, value):
        self._truncation = value

    @property
    def max_length(self):
        return self._max_length

    @max_length.setter
    def max_length(self, value):
        self._max_length = value

    @property
    def max_labels(self):
        return self._max_labels

    @max_labels.setter
    def max_labels(self, value):
        self._max_labels = value


class BaseBuilder:
    def __init__(self):
        pass

    def opt_batchifier(self, batchifier):
        self.batchifier = batchifier
        return self

    def opt_tokenizer_name(self, tokenizer_name):
        self.tokenizer_name = tokenizer_name
        return self

    def opt_vocab(self, vocab):
        if vocab is not None:
            self.vocab = vocab
        return self

    def opt_locale(self, locale):
        if locale is not None:
            self.locale = locale
        return self

    def opt_to_lower_case(self, to_lower_case):
        self.to_lower_case = to_lower_case
        return self

    def opt_include_token_types(self, include_token_types):
        self.include_token_types = include_token_types
        return self

    def opt_padding(self, padding):
        self.padding = padding
        return self

    def opt_truncation(self, truncation):
        self.truncation = truncation
        return self

    def opt_max_length(self, max_length):
        self.max_length = max_length
        return self

    def opt_max_labels(self, max_labels):
        self.max_labels = max_labels
        return self


class Translator(QATranslator):
    pass
