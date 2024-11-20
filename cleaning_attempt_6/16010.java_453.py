class PpWordRecognitionTranslatorFactory:
    SUPPORTED_TYPES = {
        (Image, str),
        (Path, str),
        (URL, str),
        (bytes, str)
    }

    def get_supported_types(self):
        return self.SUPPORTED_TYPES

    def new_instance(self, input_type: type, output_type: type, model, arguments) -> Translator:
        if input_type == Image and output_type == str:
            return PpWordRecognitionTranslator()
        elif (input_type == Path and output_type == str) or \
             (input_type == URL and output_type == str) or \
             (input_type == bytes and output_type == str):
            return FileTranslator(PpWordRecognitionTranslator())
        elif input_type == Input and output_type == Output:
            return ImageServingTranslator(PpWordRecognitionTranslator())

        raise ValueError("Unsupported input/output types.")
