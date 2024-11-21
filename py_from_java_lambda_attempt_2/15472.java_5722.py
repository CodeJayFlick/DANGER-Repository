Here's the translation of the given Java interface into a Python class:

```Python
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
```

In this translation:

- The Java interface `TextEmbedding` is converted into a Python class with similar methods and attributes. 
- In the `embed_text` method, I've added a forward slash `/` to indicate that all arguments must be specified positionally.
- The actual logic for preprocessing text, embedding text, unembedding text has been left out as it depends on specific requirements of your application. You would need to implement these methods according to your needs.

Note: This translation assumes you have the `NDManager` and `NDArray` classes available in Python. If not, you may need to import them from a library or define them yourself based on their Java counterparts.