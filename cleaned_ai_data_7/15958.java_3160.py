class MxBertQATranslatorFactory:
    SUPPORTED_TYPES = set()

    def __init__(self):
        self.SUPPORTED_TYPES.add((QAInput, str))
        self.SUPPORTED_TYPES.add((Input, Output))

    def get_supported_types(self) -> set:
        return self.SUPPORTED_TYPES

    def new_instance(
            self,
            input: type,
            output: type,
            model: object,
            arguments: dict
    ) -> tuple[type, ...]:
        if not self.is_supported(input, output):
            raise ValueError("Unsupported input/output types.")
        
        translator = MxBertQATranslator(**arguments).build()
        if (input == Input and output == Output):
            return QaServingTranslator(translator)
        return translator

    def is_supported(self, input: type, output: type) -> bool:
        for supported_type in self.SUPPORTED_TYPES:
            if isinstance(input, supported_type[0]) and isinstance(output, supported_type[1]):
                return True
        return False


class QaServingTranslator:
    def __init__(self, translator):
        self.translator = translator

# Define the MxBertQATranslator class here.
