Here is the translation of the given Java code into equivalent Python:

```Python
class PtBertQATranslatorFactory:
    SUPPORTED_TYPES = {
        (QAInput, str): None,
        (type(Input), type(Output)): QaServingTranslator
    }

    def get_supported_types(self):
        return self.SUPPORTED_TYPES

    def new_instance(self, input_type: type, output_type: type, model=None, arguments={}):
        if not self.is_supported(input_type, output_type):
            raise ValueError("Unsupported input/output types.")
        
        translator = PtBertQATranslator(**arguments)
        if (input_type == Input and output_type == Output):
            return QaServingTranslator(translator)
        else:
            return translator

    def is_supported(self, input_type: type, output_type: type) -> bool:
        for supported_types in self.SUPPORTED_TYPES.values():
            if isinstance(supported_types, tuple) and (input_type, output_type) == supported_types:
                return True
        return False


class QaServingTranslator:
    def __init__(self, translator):
        self.translator = translator

# Usage example:

factory = PtBertQATranslatorFactory()
translator = factory.new_instance(QAInput, str)
```

Note: This translation is not a direct equivalent of the Java code. Python does not have an exact equivalent to Java's `TranslatorFactory` and related classes. The above code is written in Python style with similar functionality as the original Java code.