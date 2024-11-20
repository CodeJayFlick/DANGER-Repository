class GloveWordEmbeddingTranslatorFactory:
    def get_supported_types(self):
        return [(str, list)]

    def new_instance(self, input_type: type, output_type: type, model, arguments) -> 'GloveWordEmbeddingTranslator':
        if not self.is_supported(input_type, output_type):
            raise ValueError("Unsupported input/output types.")
        
        unknown_token = arguments.get('unknownToken', None)
        return GloveWordEmbeddingTranslator(unknown_token)

    def is_supported(self, input_type: type, output_type: type) -> bool:
        # This method should be implemented to check if the given input and output types are supported.
        pass


class GloveWordEmbeddingTranslator:
    def __init__(self, unknown_token):
        self.unknown_token = unknown_token
        self.embedding = None

    def prepare(self, ctx):
        try:
            self.embedding = ctx['block']
        except ClassCastException as e:
            raise ValueError("The model was not an embedding") from e


    def process_output(self, ctx, list):
        return list


    def process_input(self, ctx, input: str) -> 'list':
        if input in self.embedding:
            return [self.embedding.embed(input)]
        else:
            return [self.embedding.embed(self.unknown_token)]


# Example usage
factory = GloveWordEmbeddingTranslatorFactory()
translator = factory.new_instance(str, list)
