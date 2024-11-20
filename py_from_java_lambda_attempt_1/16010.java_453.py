Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Note that Python does not have a direct equivalent to Java's `Set` or `Map`, so we use dictionaries (`{}`) for the supported types. Also, in Python, you don't need to specify the return type of methods as it is inferred by the compiler.

Also note that there are some minor changes made such as:

- The constructor has been removed since it's not necessary.
- `Pair` class does not exist in Python so we directly use tuples for representing pairs.
- In Java, you have a separate class for TranslatorFactory and Translator. Here, I've combined them into one class PpWordRecognitionTranslatorFactory.

Please note that this is just an equivalent translation of the given code to Python.