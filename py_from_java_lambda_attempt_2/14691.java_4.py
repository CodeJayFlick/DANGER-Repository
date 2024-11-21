Here is the translation of the given Java code into Python:

```Python
import unittest

class PipelineTest(unittest.TestCase):

    def test_add_handlers_to_pipeline(self):
        filters = Pipeline()
        filters.add_handler(RemoveAlphabetsHandler())
        filters.add_handler(RemoveDigitsHandler())
        filters.add_handler(ConvertToCharArrayHandler())

        self.assertEqual(filters.execute("#H!E(LO&L0O%THE3R#34E!"), ['#', '#', '!', '(', '&', '%', '#', '!'])

class Pipeline:
    def __init__(self):
        self.handlers = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    def execute(self, input_string):
        for handler in self.handlers:
            input_string = handler.handle(input_string)
        return list(input_string)


class RemoveAlphabetsHandler:
    def handle(self, string):
        result = ""
        for char in string:
            if not char.isalpha():
                result += char
        return result


class RemoveDigitsHandler:
    def handle(self, string):
        result = ""
        for char in string:
            if not char.isdigit():
                result += char
        return result


class ConvertToCharArrayHandler:
    def handle(self, string):
        return list(string)
```

This Python code defines a `Pipeline` class that can be used to chain together handlers. Each handler is responsible for processing the input string in some way (e.g., removing alphabets or digits). The test case demonstrates how these handlers are added and executed on an input string, with assertions made about the expected output.