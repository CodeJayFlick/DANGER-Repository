class TrainableTextEmbedding:
    def __init__(self, word_embedding):
        self.trainable_word_embedding = word_embedding

    def preprocess_text_to_embed(self, text):
        result = [0] * len(text)
        for i in range(len(text)):
            result[i] = self.trainable_word_embedding.preprocess_word_to_embed(text[i])
        return result

    def embed_text(self, text_indices):
        raise Exception("EmbedText operation is not supported by this class.")

    def unembed_text(self, text_embedding):
        split = text_embedding.split(0)
        result = []
        for token in split:
            result.append(self.trainable_word_embedding.unembed_word(token[0]))
        return result

    def forward_internal(self, parameter_store, inputs, training, params):
        return self.trainable_word_embedding.forward(parameter_store, inputs, training, params)

    def initialize_child_blocks(self, manager, data_type, *input_shapes):
        self.trainable_word_embedding.initialize(manager, data_type, input_shapes)

    def get_output_shapes(self, input_shapes):
        return self.trainable_word_embedding.get_output_shapes(input_shapes)
