Here is a translation of the Java code into equivalent Python code:

```Python
class SentencePieceLibrary:
    LIB = None  # This will be an instance variable in actual implementation.

    def __init__(self):
        pass

    @staticmethod
    def create_sentence_piece_processor():
        raise NotImplementedError("This method should return a new sentence piece processor.")

    @staticmethod
    def load_model(handle, file_path):
        raise NotImplementedError("This method should load the model with given handle and path.")

    @staticmethod
    def delete_sentence_piece_processor(handle):
        raise NotImplementedError("This method should free resources associated with the given handle.")

    @staticmethod
    def tokenize(handle, text):
        raise NotImplementedError("This method should return tokens for a given input string using the sentence piece processor at the given handle.")

    @staticmethod
    def encode(handle, text):
        raise NotImplementedError("This method should return encoded IDs for a given input string using the sentence piece processor at the given handle.")

    @staticmethod
    def detokenize(handle, tokens):
        raise NotImplementedError("This method should convert tokenized output back to original string using the sentence piece processor at the given handle.")

    @staticmethod
    def decode(handle, ids):
        raise NotImplementedError("This method should return decoded text for a given sequence of IDs using the sentence piece processor at the given handle.")

    @staticmethod
    def id_to_piece(handle, id):
        raise NotImplementedError("This method should convert an ID back to its corresponding piece string using the sentence piece processor at the given handle.")

    @staticmethod
    def piece_to_id(handle, piece):
        raise NotImplementedError("This method should return the ID for a given piece string using the sentence piece processor at the given handle.")
```

Please note that this Python code does not provide actual implementation of these methods. It only provides their signatures and raises `NotImplementedError` in each method to indicate that they are not implemented yet.