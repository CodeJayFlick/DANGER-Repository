import unittest
from io import StringIO

class GdbMiParserTest(unittest.TestCase):
    def build_field_list(self, config):
        field_list = {}
        for key, value in config.items():
            if isinstance(value, str):
                field_list[key] = [value]
            else:
                field_list[key] = value
        return field_list

    def test_match(self):
        parser = GdbMiParser(StringIO("Hello, World!"))
        self.assertEqual(parser.match(r'\w+', True), "Hello")
        self.assertEqual(parser.match(',', True), ",")

    def test_parse_string(self):
        parser = GdbMiParser(StringIO('"Hello, World!\n"'))
        self.assertEqual(parser.parse_string(), "Hello, World!\n")

    def test_parse_list(self):
        parser = GdbMiParser(StringIO('["Hello","World"]'))
        self.assertEqual(list(map(str, parser.parse_list())), ["Hello", "World"])

    def test_parse_map(self):
        parser = GdbMiParser(StringIO('{h="Hello",w="World"}'))
        field_list = self.build_field_list({"h": "Hello", "w": "World"})
        self.assertEqual(field_list, parser.parse_map())

class GdbMiParser:
    COMMA = ','

    def __init__(self, input_string):
        self.input_string = StringIO(input_string)

    def match(self, pattern, consume=True):
        import re
        if not isinstance(pattern, str) and not callable(getattr(re, 'compile', None)):
            raise TypeError("pattern must be a string or compiled regular expression")
        return self.input_string.readline().strip()

    def parse_string(self):
        result = ''
        while True:
            line = self.match(r'[^"]+|\\.[^"]*|\\\\|".*"')
            if not line.startswith('"'):
                break
            result += line.strip('"') + '\n'
        return result

    def parse_list(self):
        result = []
        for _ in range(int(self.match(r'\d+'))):
            self.match(',')
            result.append(self.parse_string())
        return [x.strip() for x in result]

    def parse_map(self):
        field_list = {}
        while True:
            line = self.input_string.readline().strip()
            if not line.startswith('{'):
                break
            key, value = line[1:].split('=', 1)
            field_list[key] = value.strip('"')
        return field_list

if __name__ == '__main__':
    unittest.main()
