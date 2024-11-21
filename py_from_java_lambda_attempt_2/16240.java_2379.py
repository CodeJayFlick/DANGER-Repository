Here is a translation of the Java code into equivalent Python code:

```Python
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
```

Note that this translation assumes the following:

1. The `SentencePieceLibrary` class is a Python wrapper around the native library, and it provides methods to load models, tokenize text, build sentences from tokens, get tokens from IDs, get IDs from tokens, encode sentences into indices, decode indices into sentences, and delete sentence piece processors.
2. The `library_status` variable is a runtime exception that represents any errors encountered while loading the native library.

Also note that this translation does not include error handling for all possible scenarios, as it would require more information about how to handle specific exceptions in Python.