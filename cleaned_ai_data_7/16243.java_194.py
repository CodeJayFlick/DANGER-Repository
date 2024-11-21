class SpVocabulary:
    def __init__(self, processor):
        self.processor = processor

    @staticmethod
    def from(tokenizer):
        return SpVocabulary(tokenizer.get_processor())

    def get_token(self, index):
        return self.processor.get_token(int(index))

    def contains(self, token):
        raise NotImplementedError("Not supported for Sentence Piece")

    def get_index(self, token):
        return self.processor.get_id(token)

    def size(self):
        raise NotImplementedError("Not supported for Sentence Piece")
