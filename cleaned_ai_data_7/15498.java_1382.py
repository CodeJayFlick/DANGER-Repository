class TextClassificationServingTranslator:
    def __init__(self, translator):
        self.translator = translator

    def get_batchifier(self):
        return self.translator.get_batchifier()

    def prepare(self, ctx):
        self.translator.prepare(ctx)

    def process_input(self, ctx, input_data):
        text = input_data['data'].get('string', '')
        return self.translator.process_input(ctx, [text])

    def process_output(self, ctx, output_list):
        ret = self.translator.process_output(ctx, output_list)
        return {'output': ret}
