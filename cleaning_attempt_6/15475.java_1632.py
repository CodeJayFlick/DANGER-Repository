class WordEmbedding:
    def vocabulary_contains(self, word: str) -> bool:
        """Returns whether an embedding exists for a word."""
        pass  # Implement this method in your subclass.

    def preprocess_word_to_embed(self, word: str) -> int:
        """Pre-processed the word to embed into an array to pass into the model."""
        pass  # Implement this method in your subclass.

    def embed_word(self, manager: 'NDManager', index: int) -> 'NDArray':
        """Embeds a word after preprocessed using preprocessWordToEmbed(String)."""
        raise EmbeddingException("Not implemented")

    def unembed_word(self, word: 'NDArray') -> str:
        """Returns the closest matching word for the given index."""
        pass  # Implement this method in your subclass.

class NDManager:
    @staticmethod
    def create(index):
        return None

class NDArray:
    pass

class EmbeddingException(Exception):
    pass
