class StyleTransferTranslatorFactory:
    def get_supported_types(self):
        from typing import Set, Tuple
        return {Tuple(Image, Image)}

    def new_instance(self, input: type, output: type, model, arguments) -> Translator:
        if not self.is_supported(input, output):
            raise ValueError("Unsupported input/output types.")
        return StyleTransferTranslator()

class Translator:
    pass

class Model:
    pass

class Image:
    pass
