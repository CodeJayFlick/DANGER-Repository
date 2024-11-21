class TrainableWordEmbedding:
    DEFAULT_UNKNOWN_TOKEN = "<unk>"

    def __init__(self):
        pass

    @classmethod
    def builder(cls):
        return cls.Builder()

    class Builder:
        def __init__(self):
            self.vocabulary = None
            self.embedding_size = 0
            self.default_item = TrainableWordEmbedding.DEFAULT_UNKNOWN_TOKEN
            self.use_default = False

        def set_vocabulary(self, vocabulary: Vocabulary) -> 'Builder':
            self.vocabulary = vocabulary
            return self

        def set_embedding_size(self, embedding_size: int) -> 'Builder':
            self.embedding_size = embedding_size
            return self

        def opt_default_item(self, default_item):
            self.default_item = default_item
            return self

        def opt_use_default(self, use_default=False):
            self.use_default = use_default
            return self

        def build(self) -> 'TrainableWordEmbedding':
            if not isinstance(self.vocabulary, Vocabulary):
                raise ValueError("Vocabulary must be an instance of Vocabulary")
            return TrainableWordEmbedding(self)


class WordEmbedding:
    pass


class Embedding(WordEmbedding):
    pass


class NDArray:
    def to_long_array(self) -> list:
        pass

    def is_scalar(self) -> bool:
        pass
