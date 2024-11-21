Here is the translation of the given Java code into equivalent Python:

```Python
class InputStreamTranslator:
    def __init__(self, translator):
        self.translator = translator

    def process_input(self, ctx, input_stream) -> list:
        image = ImageFactory.fromInputStream(input_stream)
        return self.translator.process_input(ctx, [image])

    def process_output(self, ctx, output_list) -> any:
        return self.translator.process_output(ctx, output_list)

    def get_batchifier(self):
        return self.translator.get_batchifier()

    def prepare(self, ctx):
        self.translator.prepare(ctx)
```

Note that Python does not have a direct equivalent to Java's generics. Therefore, the type parameter `<T>` in the original code has been removed from the translated Python class.

Also note that Python uses `any` as its default data type for variables without explicit types, and it does not require explicit declaration of return types like Java does with `-> T`.