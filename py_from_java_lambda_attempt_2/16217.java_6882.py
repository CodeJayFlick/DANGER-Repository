Here is the translation of the Java code to Python:

```Python
class FtWord2VecWordEmbedding:
    def __init__(self, model, vocabulary):
        self.model = model
        self.vocabulary = vocabulary

    def vocabulary_contains(self, word):
        return True

    def preprocess_word_to_embed(self, word):
        return self.vocabulary.get_index(word)

    def embed_word(self, index):
        if isinstance(index, int):
            manager = None  # Assuming NDManager is not needed in Python
            return self.embed_word(manager, [index])
        elif hasattr(index, 'getManager') and hasattr(index, 'toLongArray'):
            word = self.vocabulary.get_token(int(index.toLongArray()[0]))
            buf = self.model.fta.get_data_vector(word)
            return np.array(buf)

    def unembed_word(self, word):
        if not isinstance(word, int) or len(word.shape) > 1:
            raise ValueError("NDArray word must be scalar index")
        return self.vocabulary.get_token(int(word))
```

Note that I've made some assumptions about the Python code:

- `FtModel` and `Vocabulary` are classes with methods like `fta`, `get_data_vector`, `get_index`, etc.
- `NDArray` is a class from NumPy, which represents an array-like data structure.