class TextData:
    def __init__(self, config):
        self.text_processors = config.text_processors
        self.text_embedding = config.text_embedding
        self.vocabulary = config.vocabulary
        self.embedding_size = config.embedding_size
        self.unknown_token = config.unknown_token
        self.reserved_tokens = config.reserved_tokens

    @staticmethod
    def get_default_configuration():
        default_text_processors = [SimpleTokenizer(), LowerCaseConvertor(Locale.english), PunctuationSeparator()]
        return TextDataConfiguration().set_embedding_size(15).set_text_processors(default_text_processors).set_unknown_token("<unk>").set_reserved_tokens(["<bos>", "<eos>", "<pad>"])

    def preprocess(self, manager, new_text_data):
        self.raw_text = new_text_data
        text_data = []
        for text_datum in new_text_data:
            tokens = [text_datum]
            for processor in self.text_processors:
                tokens = processor.preprocess(tokens)
            text_data.append(tokens)

        if not self.vocabulary:
            vocabulary_builder = DefaultVocabulary.builder()
            vocabulary_builder.min_frequency(3).reserved_tokens(self.reserved_tokens).unknown_token(self.unknown_token)
            for tokens in text_data:
                vocabulary_builder.add(tokens)
            self.vocabulary = vocabulary_builder.build()

        if not self.text_embedding:
            self.text_embedding = TrainableTextEmbedding(TrainableWordEmbedding(self.vocabulary, self.embedding_size))

        self.size = len(text_data)
        self.text_embedding_list = []
        for i in range(len(text_data)):
            tokenized_text_datum = text_data[i]
            for j in range(len(tokenized_text_datum)):
                tokenized_text_datum[j] = self.vocabulary.get_token(self.vocabulary.index(tokenized_text_datum[j]))
            text_data[i] = tokenized_text_datum
            if isinstance(self.text_embedding, AbstractBlock):
                self.text_embedding_list.append(manager.create(self.text_embedding.preprocess_text_to_embed(tokenized_text_datum)))
            else:
                self.text_embedding_list.append(self.text_embedding.embed_text(manager, tokenized_text_datum))

    def set_text_processors(self, text_processors):
        self.text_processors = text_processors

    def set_text_embedding(self, text_embedding):
        self.text_embedding = text_embedding

    def get_text_embedding(self):
        return self.text_embedding

    def set_embedding_size(self, embedding_size):
        self.embedding_size = embedding_size

    def get_vocabulary(self):
        if not self.vocabulary:
            raise ValueError("This method must be called after preprocess is called on this object")
        return self.vocabulary

    def get_embedding(self, manager, index):
        embedding = self.text_embedding_list[index].duplicate()
        embedding.attach(manager)
        return embedding

    def get_raw_text(self, index):
        return self.raw_text[index]

    def get_processed_text(self, index):
        tokens = [self.get_raw_text(index)]
        for processor in self.text_processors:
            tokens = processor.preprocess(tokens)
        return tokens

    def get_size(self):
        return self.size


class TextDataConfiguration:
    def __init__(self):
        pass

    def set_text_processors(self, text_processors):
        self.text_processors = text_processors
        return self

    def set_text_embedding(self, text_embedding):
        self.text_embedding = text_embedding
        return self

    def set_vocabulary(self, vocabulary):
        self.vocabulary = vocabulary
        return self

    def set_embedding_size(self, embedding_size):
        self.embedding_size = embedding_size
        return self

    def set_unknown_token(self, unknown_token):
        self.unknown_token = unknown_token
        return self

    def set_reserved_tokens(self, reserved_tokens):
        self.reserved_tokens = reserved_tokens
        return self

    def update(self, other):
        if other.text_processors:
            self.text_processors = other.text_processors
        if other.text_embedding:
            self.text_embedding = other.text_embedding
        if other.vocabulary:
            self.vocabulary = other.vocabulary
        if other.embedding_size is not None:
            self.embedding_size = other.embedding_size
        if other.unknown_token:
            self.unknown_token = other.unknown_token
        if other.reserved_tokens:
            self.reserved_tokens = other.reserved_tokens
        return self

    def set_embedding_size(self, embedding_size):
        self.embedding_size = embedding_size
        return self


class DefaultVocabularyBuilder:
    @staticmethod
    def builder():
        pass


class SimpleTokenizer:
    def preprocess(self, tokens):
        # your implementation here
        pass


class LowerCaseConvertor:
    def __init__(self, locale):
        self.locale = locale

    def preprocess(self, tokens):
        return [token.lower() for token in tokens]


class PunctuationSeparator:
    def preprocess(self, tokens):
        return [" ".join(token.split()) for token in tokens]
