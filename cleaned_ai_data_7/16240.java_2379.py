import ctypes

class SpProcessor:
    def __init__(self):
        self.handle = SentencePieceLibrary.create_sentence_piece_processor()

    @staticmethod
    def new_instance():
        if library_status:
            raise library_status
        return SpProcessor()

    def load_model(self, path):
        SentencePieceLibrary.load_model(self.handle, path)

    def tokenize(self, input_string):
        return SentencePieceLibrary.tokenize(self.handle, input_string).decode('utf-8').split('\0')

    def build_sentence(self, tokens):
        return SentencePieceLibrary.detokenize(self.handle, ' '.join(tokens)).encode('utf-8').decode('utf-8')

    def get_token(self, id):
        return SentencePieceLibrary.id_to_piece(self.handle, id).decode('utf-8')

    def get_id(self, token):
        return SentencePieceLibrary.piece_to_id(self.handle, token.encode('utf-8')).decode('utf-8')

    def encode(self, sentence):
        return SentencePieceLibrary.encode(self.handle, sentence.encode('utf-8'))

    def decode(self, ids):
        return SentencePieceLibrary.decode(self.handle, [int(x) for x in str(ids)]).encode('utf-8').decode('utf-8')

    def close(self):
        if self.handle:
            SentencePieceLibrary.delete_sentence_piece_processor(self.handle)
