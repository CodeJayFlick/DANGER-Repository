import numpy as np

class TextEmbedding:
    def preprocess_text_to_embed(self, text):
        return [len(t) for t in text]

    def embed_text(self, manager, text_indices):
        shape = (len(text_indices), 1)
        return np.zeros(shape)

    def embed_text(self, text_indices):
        return None

    def unembed_text(self, text_embedding):
        return []

class TestUtils:
    @staticmethod
    def get_text_embedding(manager, embedding_size):
        return TextEmbedding()
