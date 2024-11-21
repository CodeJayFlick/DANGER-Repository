class PtDistilBertTranslatorFactory:
    SUPPORTED_TYPES = {
        (str, type('Classifications')): None,
        (type(Input), type(Output)): None,
    }

    def __init__(self):
        pass

    def get_supported_types(self):
        return self.SUPPORTED_TYPES.copy()

    def instance(self, input_type, output_type, model=None, arguments={}):
        if not self.is_supported(input_type, output_type):
            raise ValueError("Unsupported input/output types.")
        
        translator = PtDistilBertTranslator()
        if (input_type == type(Input) and output_type == type(Output)):
            return TextClassificationServingTranslator(translator)
        else:
            return translator

    def is_supported(self, input_type, output_type):
        for supported_types in self.SUPPORTED_TYPES.values():
            if isinstance(supported_types, dict) or not all(isinstance(k, type) for k in supported_types.keys()):
                continue
            if (input_type == list(supported_types.keys())[0] and 
                    output_type == next(iter(supported_types.values()))):
                return True

        return False


class PtDistilBertTranslator:
    pass


class TextClassificationServingTranslator:
    def __init__(self, translator):
        self.translator = translator
