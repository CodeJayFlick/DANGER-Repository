class InputStreamTranslator:
    def __init__(self, translator):
        self.translator = translator

    def process_input(self, ctx, input_stream) -> list:
        image = ImageFactory.fromInputStream(input_stream)
        return self.translator.process_input(ctx, [image])

    def process_output(self, ctx, output_list) -> any:
        return self.translator.process_output(ctx, output_list)

    def get_batchifier(self):
        return self.translator.get_batchifier()

    def prepare(self, ctx):
        self.translator.prepare(ctx)
