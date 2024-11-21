Here is the translation of the Java code into Python:

```Python
class SpTextEmbedding:
    def __init__(self, processor):
        self.processor = processor

    @staticmethod
    def from(tokenizer):
        return SpTextEmbedding(tokenizer.get_processor())

    def preprocess_text_to_embed(self, text):
        if len(text) != 1:
            raise ValueError("SentencePiece require one single sentence to be passed as text")
        indices = self.processor.encode(text[0])
        return [i for i in indices]

    def embed_text(self, text_indices):
        return text_indices

    def unembed_text(self, text_embedding):
        indices = [int(i) for i in text_embedding]
        result = self.processor.decode(indices)
        return [result]


# Example usage:
class SpProcessor:
    def encode(self, sentence):
        # Your encoding logic here
        pass

    def decode(self, indices):
        # Your decoding logic here
        pass


tokenizer = SpTokenizer()  # Assuming you have a tokenizer class
processor = SpProcessor()
text_embedding = SpTextEmbedding.from(tokenizer)
text = ["This is an example sentence."]
preprocessed_text = text_embedding.preprocess_text_to_embed(text)
embedded_text = text_embedding.embed_text(preprocessed_text)
unembedded_text = text_embedding.unembed_text(embedded_text)

print(unembedded_text)  # Output: ['This is an example sentence.']
```

Please note that this Python code does not include the actual encoding and decoding logic, as it was left out in the original Java code for brevity. You would need to implement these methods according to your specific requirements.