class NoopTranslator:
    def __init__(self):
        self.batchifier = None

    def set_batchifier(self, batchifier):
        self.batchifier = batchifier


def process_input(ctx, input_list):
    return input_list


def process_output(ctx, output_list):
    return output_list


class TranslatorContext:
    pass
