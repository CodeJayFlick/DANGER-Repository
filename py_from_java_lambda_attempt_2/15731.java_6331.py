Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `Map< Pair< Type, Type > , Translator<?, ?>>` and similar constructs. We use dictionaries (Python's built-in hash table type) to store translators by input/output types.

Also, in the given code there are references to classes like `ServingTranslatorFactory`, `ImageClassificationTranslatorFactory`, `NoopTranslator`. These need to be implemented separately as Python classes or functions depending on their functionality.