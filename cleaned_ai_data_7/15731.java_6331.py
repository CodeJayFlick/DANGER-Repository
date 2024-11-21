class DefaultTranslatorFactory:
    def __init__(self):
        self.translators = {}

    def register_translator(self, input_type: type, output_type: type, translator) -> None:
        if not self.translators:
            self.translators = {}
        self.translators[(input_type, output_type)] = translator

    def get_supported_types(self):
        supported_types = set()
        if self.translators:
            supported_types.update(self.translators.keys())
        return {NDList: NDList} | supported_types

    def is_supported(self, input_type: type, output_type: type) -> bool:
        if (input_type == NDList and output_type == NDList):
            return True
        if self.translators.get((input_type, output_type)):
            return True
        return any([self.serving_translator_factory.is_supported(input_type, output_type),
                    self.image_classification_translator_factory.is_supported(input_type, output_type)])

    def new_instance(self, input_type: type, output_type: type, model, arguments) -> 'Translator':
        if self.translators:
            translator = self.translators.get((input_type, output_type))
            if translator:
                return translator
        if (input_type == NDList and output_type == NDList):
            return NoopTranslator()
        if self.serving_translator_factory.is_supported(input_type, output_type):
            return self.serving_translator_factory.new_instance(input_type, output_type, model, arguments)
        if self.image_classification_translator_factory.is_supported(input_type, output_type):
            return self.image_classification_translator_factory.new_instance(
                input_type, output_type, model, arguments
            )
        return None

    @property
    def serving_translator_factory(self) -> 'ServingTranslatorFactory':
        return ServingTranslatorFactory()

    @property
    def image_classification_translator_factory(self) -> 'ImageClassificationTranslatorFactory':
        return ImageClassificationTranslatorFactory()
