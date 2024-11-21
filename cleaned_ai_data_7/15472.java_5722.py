class TextEmbedding:
    def preprocess_text_to_embed(self, texts: list[str]) -> list[int]:
        # Implement your preprocessing logic here.
        pass

    def embed_text(self, manager: NDManager, text_indices: list[int], /) -> NDArray:
        return self.embed_text(manager.create(text_indices))

    def embed_text(self, text_indices: NDArray,) -> NDArray:
        raise EmbeddingException("Embedding not implemented")

    def unembed_text(self, text_embedding: NDArray,) -> list[str]:
        # Implement your logic to find the closest matching text for a given embedding here.
        pass


class EmbeddingException(Exception):
    pass
