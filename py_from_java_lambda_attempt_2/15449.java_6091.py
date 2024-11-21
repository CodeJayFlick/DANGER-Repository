Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's `Class` type. In the above code, I used Python's built-in `type`. Also, in Python, we don't need to explicitly define a constructor (`__init__`) for classes as it is automatically provided by Python.

The given Java code seems to be part of an AI/ML framework (DJI-Lite) and might require additional libraries or modules not included here.